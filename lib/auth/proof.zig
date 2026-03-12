const std = @import("std");
const challenge_mod = @import("challenge.zig");
const identity = @import("../identity.zig");

pub const Proof = struct {
    did: []u8,
    signature: identity.Signature,

    pub fn deinit(self: *Proof, allocator: std.mem.Allocator) void {
        allocator.free(self.did);
    }
};

pub fn signChallenge(
    allocator: std.mem.Allocator,
    key_pair: identity.KeyPair,
    did: []const u8,
    challenge: challenge_mod.Challenge,
) !Proof {
    const payload = try challenge.payloadAlloc(allocator, did);
    defer allocator.free(payload);

    return .{
        .did = try allocator.dupe(u8, did),
        .signature = try key_pair.sign(payload),
    };
}

test "signChallenge creates a proof that matches the identity key" {
    const allocator = std.testing.allocator;
    const key_pair = try identity.KeyPair.fromSeed([_]u8{0x66} ** 32);
    const challenge = challenge_mod.Challenge.fromTranscript([_]u8{0x77} ** 32, "proof-transcript", .client);
    const did = "did:key:zproof";

    var proof = try signChallenge(allocator, key_pair, did, challenge);
    defer proof.deinit(allocator);

    const payload = try challenge.payloadAlloc(allocator, did);
    defer allocator.free(payload);

    try std.testing.expectEqualStrings(did, proof.did);
    try std.testing.expect(identity.verifyWithPublicKey(payload, proof.signature, key_pair.public_key));
}
