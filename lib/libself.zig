pub const base58btc = @import("base58btc.zig");
pub const identity = @import("identity.zig");
pub const NodeId = @import("node_id.zig").NodeId;
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
    pub const policy = @import("trust/policy.zig");
    pub const store = @import("trust/store.zig");
};
pub const DidKey = did.key.DidKey;
pub const Document = did.document.Document;
pub const resolveDidKey = did.resolver.resolveDidKey;
pub const Challenge = auth.challenge.Challenge;
pub const Proof = auth.proof.Proof;
pub const TrustMode = trust.policy.Mode;
pub const TrustDecision = trust.policy.Decision;
pub const TrustStore = trust.store.Store;

pub fn hello() []const u8 {
    return "hello from libself";
}

test {
    const allocator = @import("std").testing.allocator;
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

    try @import("std").testing.expectEqualStrings("hello from libself", hello());
    try @import("std").testing.expectEqualStrings(did_uri, document.id);
    try @import("std").testing.expectEqual(
        TrustDecision.accepted_and_pinned,
        try store.evaluate(.tofu, "peer-a", did_uri),
    );
}
