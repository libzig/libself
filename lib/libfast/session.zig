const std = @import("std");
const proof_mod = @import("../auth/proof.zig");
const did_key = @import("../did/key.zig");
const adapter = @import("adapter.zig");
const binding_mod = @import("binding.zig");
const libfast = @import("libfast");
const messages = @import("messages.zig");
const types = @import("types.zig");
const trust_policy = @import("../trust/policy.zig");
const trust_store = @import("../trust/store.zig");
const identity = @import("../identity.zig");

pub const VerifyError = error{
    RoleMismatch,
    TrustRejected,
    InvalidDid,
    InvalidSignature,
} || std.mem.Allocator.Error;

pub const VerifyConnectionError = VerifyError || binding_mod.Error;

pub fn localAuthContext(
    allocator: std.mem.Allocator,
    connection: *const libfast.QuicConnection,
    subject: []const u8,
) binding_mod.Error!types.AuthContext {
    return .{
        .subject = subject,
        .role = adapter.localRole(connection),
        .binding = try binding_mod.transcriptBinding(allocator, connection),
    };
}

pub fn peerAuthContext(
    allocator: std.mem.Allocator,
    connection: *const libfast.QuicConnection,
    subject: []const u8,
) binding_mod.Error!types.AuthContext {
    return .{
        .subject = subject,
        .role = adapter.peerRole(connection),
        .binding = try binding_mod.transcriptBinding(allocator, connection),
    };
}

pub fn newChallengeMessage(context: types.AuthContext, nonce: [32]u8) messages.ChallengeMessage {
    return .{
        .role = context.role,
        .nonce = nonce,
    };
}

pub fn newPeerChallengeMessage(
    allocator: std.mem.Allocator,
    connection: *const libfast.QuicConnection,
    subject: []const u8,
    nonce: [32]u8,
) binding_mod.Error!messages.ChallengeMessage {
    const context = try peerAuthContext(allocator, connection, subject);
    return newChallengeMessage(context, nonce);
}

pub fn signProofMessage(
    allocator: std.mem.Allocator,
    key_pair: identity.KeyPair,
    did: []const u8,
    context: types.AuthContext,
    challenge_message: messages.ChallengeMessage,
) !messages.ProofMessage {
    if (challenge_message.role != context.role) return error.RoleMismatch;

    const challenge = context.challenge(challenge_message.nonce);
    var proof = try proof_mod.signChallenge(allocator, key_pair, did, challenge);
    defer proof.deinit(allocator);

    return messages.ProofMessage.fromProof(allocator, proof);
}

pub fn signLocalProofMessage(
    allocator: std.mem.Allocator,
    connection: *const libfast.QuicConnection,
    key_pair: identity.KeyPair,
    did: []const u8,
    challenge_message: messages.ChallengeMessage,
) !messages.ProofMessage {
    const context = try localAuthContext(allocator, connection, "");
    return signProofMessage(allocator, key_pair, did, context, challenge_message);
}

pub fn verifyProofMessage(
    allocator: std.mem.Allocator,
    mode: trust_policy.Mode,
    store: *trust_store.Store,
    context: types.AuthContext,
    challenge_message: messages.ChallengeMessage,
    proof_message: messages.ProofMessage,
) VerifyError!types.PeerIdentity {
    if (challenge_message.role != context.role) return error.RoleMismatch;

    const challenge = context.challenge(challenge_message.nonce);
    var proof = try proof_message.toProof(allocator);
    defer proof.deinit(allocator);

    proof_mod.verifyProof(allocator, challenge, proof) catch |err| switch (err) {
        error.InvalidDid => return error.InvalidDid,
        error.InvalidSignature => return error.InvalidSignature,
        else => return err,
    };

    const parsed = did_key.DidKey.parse(allocator, proof_message.did) catch {
        return error.InvalidDid;
    };

    const decision = try store.evaluate(mode, context.subject, proof_message.did);
    if (decision == .rejected) return error.TrustRejected;

    return types.PeerIdentity.init(allocator, proof_message.did, parsed.public_key, decision);
}

pub fn verifyPeerProofMessage(
    allocator: std.mem.Allocator,
    mode: trust_policy.Mode,
    store: *trust_store.Store,
    connection: *const libfast.QuicConnection,
    subject: []const u8,
    challenge_message: messages.ChallengeMessage,
    proof_message: messages.ProofMessage,
) VerifyConnectionError!types.PeerIdentity {
    const context = try peerAuthContext(allocator, connection, subject);
    return verifyProofMessage(allocator, mode, store, context, challenge_message, proof_message);
}

fn initNegotiatedClient(allocator: std.mem.Allocator, seed: u8) !libfast.QuicConnection {
    var connection = try libfast.QuicConnection.init(
        allocator,
        libfast.QuicConfig.sshClient("example.com", ""),
    );
    errdefer connection.deinit();

    const internal = try allocator.create(libfast.connection.Connection);
    errdefer allocator.destroy(internal);

    const local_cid = try libfast.ConnectionId.init(&([_]u8{seed} ** 8));
    const remote_cid = try libfast.ConnectionId.init(&([_]u8{seed +% 1} ** 8));
    internal.* = try libfast.connection.Connection.initClient(allocator, .ssh, local_cid, remote_cid);
    connection.internal_conn = internal;

    const encoded_params = try libfast.transport_params.TransportParams.defaultServer().encode(allocator);
    defer allocator.free(encoded_params);

    try connection.applyPeerTransportParams(encoded_params);
    connection.state = .established;
    return connection;
}

test "libfast session derives auth contexts from a negotiated connection" {
    const allocator = std.testing.allocator;
    var connection = try initNegotiatedClient(allocator, 0xa1);
    defer connection.deinit();

    const local = try localAuthContext(allocator, &connection, "self");
    const peer = try peerAuthContext(allocator, &connection, "peer-a");

    try std.testing.expectEqualStrings("self", local.subject);
    try std.testing.expectEqualStrings("peer-a", peer.subject);
    try std.testing.expectEqual(@as(@TypeOf(local.role), .client), local.role);
    try std.testing.expectEqual(@as(@TypeOf(peer.role), .server), peer.role);
    try std.testing.expectEqualSlices(u8, &local.binding.hash, &peer.binding.hash);
}

test "libfast session signs and verifies a proof message" {
    const allocator = std.testing.allocator;
    const key_pair = try identity.KeyPair.fromSeed([_]u8{0x71} ** 32);
    const did = try did_key.DidKey.fromKeyPair(key_pair).encode(allocator);
    defer allocator.free(did);

    const context = types.AuthContext{
        .subject = "peer-a",
        .role = .server,
        .binding = types.TranscriptBinding.fromTranscript("libfast-session"),
    };
    const challenge_message = newChallengeMessage(context, [_]u8{0x72} ** 32);
    var proof_message = try signProofMessage(allocator, key_pair, did, context, challenge_message);
    defer proof_message.deinit(allocator);

    var store = trust_store.Store.init(allocator);
    defer store.deinit();
    var peer = try verifyProofMessage(allocator, .tofu, &store, context, challenge_message, proof_message);
    defer peer.deinit();

    try std.testing.expectEqualStrings(did, peer.did);
    try std.testing.expectEqual(trust_policy.Decision.accepted_and_pinned, peer.trust);
}

test "libfast session creates a peer challenge from the connection role" {
    const allocator = std.testing.allocator;
    var connection = try initNegotiatedClient(allocator, 0xa2);
    defer connection.deinit();

    const nonce = [_]u8{0x33} ** 32;
    const challenge = try newPeerChallengeMessage(allocator, &connection, "peer-a", nonce);

    try std.testing.expectEqual(messages.ChallengeMessage{
        .role = .server,
        .nonce = nonce,
    }, challenge);
}

test "libfast session rejects proof replayed against a different transcript" {
    const allocator = std.testing.allocator;
    const key_pair = try identity.KeyPair.fromSeed([_]u8{0x81} ** 32);
    const did = try did_key.DidKey.fromKeyPair(key_pair).encode(allocator);
    defer allocator.free(did);

    const original_context = types.AuthContext{
        .subject = "peer-a",
        .role = .client,
        .binding = types.TranscriptBinding.fromTranscript("original-transcript"),
    };
    const replay_context = types.AuthContext{
        .subject = "peer-a",
        .role = .client,
        .binding = types.TranscriptBinding.fromTranscript("replayed-transcript"),
    };
    const challenge_message = newChallengeMessage(original_context, [_]u8{0x82} ** 32);
    var proof_message = try signProofMessage(allocator, key_pair, did, original_context, challenge_message);
    defer proof_message.deinit(allocator);

    var store = trust_store.Store.init(allocator);
    defer store.deinit();

    try std.testing.expectError(
        error.InvalidSignature,
        verifyProofMessage(allocator, .accept_any, &store, replay_context, challenge_message, proof_message),
    );
}

test "libfast session enforces trust policy" {
    const allocator = std.testing.allocator;
    const first = try identity.KeyPair.fromSeed([_]u8{0x91} ** 32);
    const second = try identity.KeyPair.fromSeed([_]u8{0x92} ** 32);
    const first_did = try did_key.DidKey.fromKeyPair(first).encode(allocator);
    defer allocator.free(first_did);
    const second_did = try did_key.DidKey.fromKeyPair(second).encode(allocator);
    defer allocator.free(second_did);

    const context = types.AuthContext{
        .subject = "peer-a",
        .role = .server,
        .binding = types.TranscriptBinding.fromTranscript("trust-transcript"),
    };
    const challenge_message = newChallengeMessage(context, [_]u8{0x93} ** 32);

    var store = trust_store.Store.init(allocator);
    defer store.deinit();

    var first_message = try signProofMessage(allocator, first, first_did, context, challenge_message);
    defer first_message.deinit(allocator);
    var first_peer = try verifyProofMessage(allocator, .tofu, &store, context, challenge_message, first_message);
    defer first_peer.deinit();

    var second_message = try signProofMessage(allocator, second, second_did, context, challenge_message);
    defer second_message.deinit(allocator);

    try std.testing.expectError(
        error.TrustRejected,
        verifyProofMessage(allocator, .tofu, &store, context, challenge_message, second_message),
    );
}

test "libfast session signs a proof from the negotiated local role" {
    const allocator = std.testing.allocator;
    var connection = try initNegotiatedClient(allocator, 0xa3);
    defer connection.deinit();

    const key_pair = try identity.KeyPair.fromSeed([_]u8{0x44} ** 32);
    const did = try did_key.DidKey.fromKeyPair(key_pair).encode(allocator);
    defer allocator.free(did);

    const context = try localAuthContext(allocator, &connection, "");
    const challenge_message = messages.ChallengeMessage{
        .role = .client,
        .nonce = [_]u8{0x45} ** 32,
    };
    var proof_message = try signLocalProofMessage(
        allocator,
        &connection,
        key_pair,
        did,
        challenge_message,
    );
    defer proof_message.deinit(allocator);

    var proof = try proof_message.toProof(allocator);
    defer proof.deinit(allocator);

    try proof_mod.verifyProof(allocator, context.challenge(challenge_message.nonce), proof);
}

test "libfast session verifies a peer proof from the negotiated connection" {
    const allocator = std.testing.allocator;
    var connection = try initNegotiatedClient(allocator, 0xa4);
    defer connection.deinit();

    const key_pair = try identity.KeyPair.fromSeed([_]u8{0x55} ** 32);
    const did = try did_key.DidKey.fromKeyPair(key_pair).encode(allocator);
    defer allocator.free(did);

    const challenge_message = try newPeerChallengeMessage(
        allocator,
        &connection,
        "peer-a",
        [_]u8{0x56} ** 32,
    );
    const peer_context = try peerAuthContext(allocator, &connection, "peer-a");
    var proof_message = try signProofMessage(
        allocator,
        key_pair,
        did,
        peer_context,
        challenge_message,
    );
    defer proof_message.deinit(allocator);

    var store = trust_store.Store.init(allocator);
    defer store.deinit();
    var peer = try verifyPeerProofMessage(
        allocator,
        .tofu,
        &store,
        &connection,
        "peer-a",
        challenge_message,
        proof_message,
    );
    defer peer.deinit();

    try std.testing.expectEqualStrings(did, peer.did);
    try std.testing.expectEqual(trust_policy.Decision.accepted_and_pinned, peer.trust);
}
