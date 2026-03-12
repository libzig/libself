const std = @import("std");
const adapter = @import("adapter.zig");
const libfast = @import("libfast");
const local_identity = @import("local_identity.zig");
const messages = @import("messages.zig");
const node_id = @import("../node_id.zig");
const proof_mod = @import("../auth/proof.zig");
const session = @import("session.zig");
const trust_policy = @import("../trust/policy.zig");
const trust_store = @import("../trust/store.zig");
const types = @import("types.zig");

pub const AuthenticatedConnection = struct {
    allocator: std.mem.Allocator,
    connection: *libfast.QuicConnection,
    peer_subject: []u8,
    peer: ?types.PeerIdentity = null,

    pub fn init(
        allocator: std.mem.Allocator,
        connection: *libfast.QuicConnection,
        peer_subject: []const u8,
    ) !AuthenticatedConnection {
        try adapter.requireHandshakeReady(connection);
        return .{
            .allocator = allocator,
            .connection = connection,
            .peer_subject = try allocator.dupe(u8, peer_subject),
        };
    }

    pub fn deinit(self: *AuthenticatedConnection) void {
        self.clearPeer();
        self.allocator.free(self.peer_subject);
    }

    pub fn subject(self: *const AuthenticatedConnection) []const u8 {
        return self.peer_subject;
    }

    pub fn isAuthenticated(self: *const AuthenticatedConnection) bool {
        return self.peer != null;
    }

    pub fn attachPeer(self: *AuthenticatedConnection, peer: types.PeerIdentity) void {
        self.clearPeer();
        self.peer = peer;
    }

    pub fn clearPeer(self: *AuthenticatedConnection) void {
        if (self.peer) |*peer| {
            peer.deinit();
            self.peer = null;
        }
    }

    pub fn peerDid(self: *const AuthenticatedConnection) ?[]const u8 {
        return if (self.peer) |peer| peer.did else null;
    }

    pub fn peerNodeId(self: *const AuthenticatedConnection) ?node_id.NodeId {
        return if (self.peer) |peer| peer.node_id else null;
    }

    pub fn peerTrust(self: *const AuthenticatedConnection) ?trust_policy.Decision {
        return if (self.peer) |peer| peer.trust else null;
    }

    pub fn localContext(self: *const AuthenticatedConnection) !types.AuthContext {
        return session.localAuthContext(self.allocator, self.connection, "");
    }

    pub fn peerContext(self: *const AuthenticatedConnection) !types.AuthContext {
        return session.peerAuthContext(self.allocator, self.connection, self.peer_subject);
    }

    pub fn newPeerChallenge(
        self: *const AuthenticatedConnection,
        nonce: [32]u8,
    ) !messages.ChallengeMessage {
        return session.newPeerChallengeMessage(
            self.allocator,
            self.connection,
            self.peer_subject,
            nonce,
        );
    }

    pub fn signLocalProof(
        self: *const AuthenticatedConnection,
        local: local_identity.LocalIdentity,
        challenge: messages.ChallengeMessage,
    ) !messages.ProofMessage {
        return session.signLocalProofMessage(
            self.allocator,
            self.connection,
            local.key_pair,
            local.did,
            challenge,
        );
    }

    pub fn verifyPeerProof(
        self: *AuthenticatedConnection,
        mode: trust_policy.Mode,
        store: *trust_store.Store,
        challenge: messages.ChallengeMessage,
        proof: messages.ProofMessage,
    ) !trust_policy.Decision {
        const peer = try session.verifyPeerProofMessage(
            self.allocator,
            mode,
            store,
            self.connection,
            self.peer_subject,
            challenge,
            proof,
        );
        const decision = peer.trust;
        self.attachPeer(peer);
        return decision;
    }
};

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

test "authenticated connection requires handshake-ready transport" {
    var connection = try libfast.QuicConnection.init(
        std.testing.allocator,
        libfast.QuicConfig.sshClient("example.com", ""),
    );
    defer connection.deinit();

    try std.testing.expectError(
        error.HandshakeNotReady,
        AuthenticatedConnection.init(std.testing.allocator, &connection, "peer-a"),
    );
}

test "authenticated connection stores subject and starts unauthenticated" {
    const allocator = std.testing.allocator;
    var connection = try initNegotiatedClient(allocator, 0x91);
    defer connection.deinit();

    var attached = try AuthenticatedConnection.init(allocator, &connection, "peer-a");
    defer attached.deinit();

    try std.testing.expectEqualStrings("peer-a", attached.subject());
    try std.testing.expect(!attached.isAuthenticated());
}

test "authenticated connection attaches and clears peer identity" {
    const allocator = std.testing.allocator;
    var connection = try initNegotiatedClient(allocator, 0x92);
    defer connection.deinit();

    var attached = try AuthenticatedConnection.init(allocator, &connection, "peer-a");
    defer attached.deinit();

    const public_key = [_]u8{0x44} ** 32;
    attached.attachPeer(try types.PeerIdentity.init(
        allocator,
        "did:key:zpeer-a",
        public_key,
        .accepted,
    ));

    try std.testing.expect(attached.isAuthenticated());
    try std.testing.expectEqualStrings("did:key:zpeer-a", attached.peerDid().?);
    try std.testing.expectEqual(trust_policy.Decision.accepted, attached.peerTrust().?);
    try std.testing.expectEqual(node_id.NodeId.fromPublicKey(public_key), attached.peerNodeId().?);

    attached.clearPeer();

    try std.testing.expect(!attached.isAuthenticated());
    try std.testing.expect(attached.peerDid() == null);
    try std.testing.expect(attached.peerNodeId() == null);
    try std.testing.expect(attached.peerTrust() == null);
}

test "authenticated connection replaces an existing peer identity" {
    const allocator = std.testing.allocator;
    var connection = try initNegotiatedClient(allocator, 0x93);
    defer connection.deinit();

    var attached = try AuthenticatedConnection.init(allocator, &connection, "peer-a");
    defer attached.deinit();

    attached.attachPeer(try types.PeerIdentity.init(
        allocator,
        "did:key:zfirst",
        [_]u8{0x51} ** 32,
        .accepted,
    ));
    attached.attachPeer(try types.PeerIdentity.init(
        allocator,
        "did:key:zsecond",
        [_]u8{0x52} ** 32,
        .accepted_and_pinned,
    ));

    try std.testing.expectEqualStrings("did:key:zsecond", attached.peerDid().?);
    try std.testing.expectEqual(trust_policy.Decision.accepted_and_pinned, attached.peerTrust().?);
}

test "authenticated connection builds peer challenge from attached subject" {
    const allocator = std.testing.allocator;
    var connection = try initNegotiatedClient(allocator, 0x94);
    defer connection.deinit();

    var attached = try AuthenticatedConnection.init(allocator, &connection, "peer-b");
    defer attached.deinit();

    const nonce = [_]u8{0x61} ** 32;
    const challenge = try attached.newPeerChallenge(nonce);

    try std.testing.expectEqual(@as(@TypeOf(challenge.role), .server), challenge.role);
    try std.testing.expectEqualSlices(u8, &nonce, &challenge.nonce);
}

test "authenticated connection derives local and peer contexts" {
    const allocator = std.testing.allocator;
    var connection = try initNegotiatedClient(allocator, 0x97);
    defer connection.deinit();

    var attached = try AuthenticatedConnection.init(allocator, &connection, "peer-z");
    defer attached.deinit();

    const local = try attached.localContext();
    const peer = try attached.peerContext();

    try std.testing.expectEqual(@as(@TypeOf(local.role), .client), local.role);
    try std.testing.expectEqual(@as(@TypeOf(peer.role), .server), peer.role);
    try std.testing.expectEqualStrings("", local.subject);
    try std.testing.expectEqualStrings("peer-z", peer.subject);
    try std.testing.expectEqualSlices(u8, &local.binding.hash, &peer.binding.hash);
}

test "authenticated connection signs local proof with attached transport binding" {
    const allocator = std.testing.allocator;
    var connection = try initNegotiatedClient(allocator, 0x95);
    defer connection.deinit();

    var attached = try AuthenticatedConnection.init(allocator, &connection, "peer-c");
    defer attached.deinit();
    var local = try local_identity.LocalIdentity.fromSeed(allocator, [_]u8{0x71} ** 32);
    defer local.deinit();

    const challenge = messages.ChallengeMessage{
        .role = .client,
        .nonce = [_]u8{0x72} ** 32,
    };
    var proof = try attached.signLocalProof(local, challenge);
    defer proof.deinit(allocator);

    const context = try session.localAuthContext(allocator, &connection, "");
    var decoded = try proof.toProof(allocator);
    defer decoded.deinit(allocator);

    try proof_mod.verifyProof(
        allocator,
        context.challenge(challenge.nonce),
        decoded,
    );
}

test "authenticated connection verifies and attaches peer identity" {
    const allocator = std.testing.allocator;
    var connection = try initNegotiatedClient(allocator, 0x96);
    defer connection.deinit();

    var attached = try AuthenticatedConnection.init(allocator, &connection, "peer-d");
    defer attached.deinit();

    var peer_local = try local_identity.LocalIdentity.fromSeed(allocator, [_]u8{0x81} ** 32);
    defer peer_local.deinit();

    const challenge = try attached.newPeerChallenge([_]u8{0x82} ** 32);
    const peer_context = try session.peerAuthContext(allocator, &connection, "peer-d");
    var proof = try session.signProofMessage(
        allocator,
        peer_local.key_pair,
        peer_local.did,
        peer_context,
        challenge,
    );
    defer proof.deinit(allocator);

    var store = trust_store.Store.init(allocator);
    defer store.deinit();

    const decision = try attached.verifyPeerProof(.tofu, &store, challenge, proof);

    try std.testing.expectEqual(trust_policy.Decision.accepted_and_pinned, decision);
    try std.testing.expect(attached.isAuthenticated());
    try std.testing.expectEqualStrings(peer_local.did, attached.peerDid().?);
    try std.testing.expectEqual(trust_policy.Decision.accepted_and_pinned, attached.peerTrust().?);
}
