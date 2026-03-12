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
    pub const binding = @import("libfast/binding.zig");
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
pub const LibfastPeerIdentity = libfast.types.PeerIdentity;
pub const LibfastChallengeMessage = libfast.messages.ChallengeMessage;
pub const LibfastProofMessage = libfast.messages.ProofMessage;

pub fn hello() []const u8 {
    return "hello from libself";
}

test {
    const std = @import("std");
    std.testing.refAllDecls(@This());

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

    const libfast_context = LibfastAuthContext{
        .subject = "peer-a",
        .role = .server,
        .binding = LibfastTranscriptBinding.fromTranscript("libself-smoke"),
    };
    const libfast_challenge = libfast.session.newChallengeMessage(libfast_context, [_]u8{0xbb} ** 32);
    var libfast_proof = try libfast.session.signProofMessage(
        allocator,
        key_pair,
        did_uri,
        libfast_context,
        libfast_challenge,
    );
    defer libfast_proof.deinit(allocator);

    var libfast_peer = try libfast.session.verifyProofMessage(
        allocator,
        .tofu,
        &store,
        libfast_context,
        libfast_challenge,
        libfast_proof,
    );
    defer libfast_peer.deinit();

    try std.testing.expectEqualStrings("hello from libself", hello());
    try std.testing.expectEqualStrings(did_uri, document.id);
    try std.testing.expectEqual(
        TrustDecision.accepted_and_pinned,
        libfast_peer.trust,
    );
    try std.testing.expectEqualStrings(did_uri, libfast_peer.did);
}
