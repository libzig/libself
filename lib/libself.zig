pub const base58btc = @import("base58btc.zig");
pub const identity = @import("identity.zig");
pub const NodeId = @import("node_id.zig").NodeId;
pub const Profile = @import("profile.zig").Profile;
pub const did = struct {
    pub const document = @import("did/document.zig");
    pub const key = @import("did/key.zig");
    pub const resolver = @import("did/resolver.zig");
};
pub const auth = struct {
    pub const challenge = @import("auth/challenge.zig");
    pub const proof = @import("auth/proof.zig");
};
pub const trust = struct {
    pub const file = @import("trust/file.zig");
    pub const policy = @import("trust/policy.zig");
    pub const store = @import("trust/store.zig");
};
pub const libfast = struct {
    pub const adapter = @import("libfast/adapter.zig");
    pub const attached = @import("libfast/attached.zig");
    pub const binding = @import("libfast/binding.zig");
    pub const local_identity = @import("libfast/local_identity.zig");
    pub const messages = @import("libfast/messages.zig");
    pub const session = @import("libfast/session.zig");
    pub const types = @import("libfast/types.zig");
};
pub const DidKey = did.key.DidKey;
pub const Document = did.document.Document;
pub const resolveDidKey = did.resolver.resolveDidKey;
pub const Challenge = auth.challenge.Challenge;
pub const Proof = auth.proof.Proof;
pub const TrustMode = trust.policy.Mode;
pub const TrustDecision = trust.policy.Decision;
pub const TrustStore = trust.store.Store;
pub const LibfastTranscriptBinding = libfast.types.TranscriptBinding;
pub const LibfastAuthContext = libfast.types.AuthContext;
pub const LibfastAuthenticatedConnection = libfast.attached.AuthenticatedConnection;
pub const LibfastLocalIdentity = libfast.local_identity.LocalIdentity;
pub const LibfastPeerIdentity = libfast.types.PeerIdentity;
pub const LibfastChallengeMessage = libfast.messages.ChallengeMessage;
pub const LibfastProofMessage = libfast.messages.ProofMessage;

pub fn hello() []const u8 {
    return "hello from libself";
}

test {
    const std = @import("std");
    const raw_libfast = @import("libfast");
    const helper = struct {
        fn initNegotiatedClient(alloc: std.mem.Allocator, seed: u8) !raw_libfast.QuicConnection {
            var conn = try raw_libfast.QuicConnection.init(
                alloc,
                raw_libfast.QuicConfig.sshClient("example.com", ""),
            );
            errdefer conn.deinit();

            const internal = try alloc.create(raw_libfast.connection.Connection);
            errdefer alloc.destroy(internal);

            const local_cid = try raw_libfast.ConnectionId.init(&([_]u8{seed} ** 8));
            const remote_cid = try raw_libfast.ConnectionId.init(&([_]u8{seed +% 1} ** 8));
            internal.* = try raw_libfast.connection.Connection.initClient(alloc, .ssh, local_cid, remote_cid);
            conn.internal_conn = internal;

            const encoded_params = try raw_libfast.transport_params.TransportParams.defaultServer().encode(alloc);
            defer alloc.free(encoded_params);

            try conn.applyPeerTransportParams(encoded_params);
            conn.state = .established;
            return conn;
        }
    };
    std.testing.refAllDecls(@This());
    std.testing.refAllDecls(base58btc);
    std.testing.refAllDecls(identity);
    std.testing.refAllDecls(did.document);
    std.testing.refAllDecls(did.key);
    std.testing.refAllDecls(did.resolver);
    std.testing.refAllDecls(auth.challenge);
    std.testing.refAllDecls(auth.proof);
    std.testing.refAllDecls(trust.file);
    std.testing.refAllDecls(trust.policy);
    std.testing.refAllDecls(trust.store);
    std.testing.refAllDecls(libfast.adapter);
    std.testing.refAllDecls(libfast.attached);
    std.testing.refAllDecls(libfast.binding);
    std.testing.refAllDecls(libfast.local_identity);
    std.testing.refAllDecls(libfast.messages);
    std.testing.refAllDecls(libfast.session);
    std.testing.refAllDecls(libfast.types);

    const allocator = std.testing.allocator;
    const key_pair = try identity.KeyPair.fromSeed([_]u8{0x99} ** 32);
    const did_uri = try DidKey.fromKeyPair(key_pair).encode(allocator);
    defer allocator.free(did_uri);

    var document = try resolveDidKey(allocator, did_uri);
    defer document.deinit(allocator);

    const challenge = Challenge.fromTranscript([_]u8{0xaa} ** 32, "libself-smoke", .client);
    var proof = try auth.proof.signChallenge(allocator, key_pair, did_uri, challenge);
    defer proof.deinit(allocator);

    try auth.proof.verifyProof(allocator, challenge, proof);

    var store = TrustStore.init(allocator);
    defer store.deinit();

    var connection = try helper.initNegotiatedClient(allocator, 0xbb);
    defer connection.deinit();
    var attached = try LibfastAuthenticatedConnection.init(allocator, &connection, "peer-a");
    defer attached.deinit();

    var peer_local = try LibfastLocalIdentity.fromSeed(allocator, [_]u8{0xbc} ** 32);
    defer peer_local.deinit();

    const libfast_challenge = try attached.newPeerChallenge([_]u8{0xbd} ** 32);
    const libfast_context = try attached.peerContext();
    var libfast_proof = try libfast.session.signProofMessage(
        allocator,
        peer_local.key_pair,
        peer_local.did,
        libfast_context,
        libfast_challenge,
    );
    defer libfast_proof.deinit(allocator);

    const libfast_decision = try attached.verifyPeerProof(
        .tofu,
        &store,
        libfast_challenge,
        libfast_proof,
    );

    try std.testing.expectEqualStrings("hello from libself", hello());
    try std.testing.expectEqualStrings(did_uri, document.id);
    try std.testing.expectEqual(TrustDecision.accepted_and_pinned, libfast_decision);
    try std.testing.expect(attached.isAuthenticated());
    try std.testing.expectEqualStrings(peer_local.did, attached.peerDid().?);
    try std.testing.expectEqual(TrustDecision.accepted_and_pinned, attached.peerTrust().?);

    const attached_node_id = attached.peerNodeId().?;
    const expected_node_id = NodeId.fromPublicKey(peer_local.key_pair.public_key);
    try std.testing.expectEqualSlices(u8, &expected_node_id.toBytes(), &attached_node_id.toBytes());
}
