const std = @import("std");
const challenge_mod = @import("challenge.zig");
const did_key = @import("../did/key.zig");
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

pub const VerifyError = error{
    InvalidDid,
    InvalidSignature,
} || std.mem.Allocator.Error;

pub fn verifyProof(
    allocator: std.mem.Allocator,
    challenge: challenge_mod.Challenge,
    proof: Proof,
) VerifyError!void {
    const parsed = did_key.DidKey.parse(allocator, proof.did) catch {
        return error.InvalidDid;
    };

    const payload = try challenge.payloadAlloc(allocator, proof.did);
    defer allocator.free(payload);

    if (!identity.verifyWithPublicKey(payload, proof.signature, parsed.public_key)) {
        return error.InvalidSignature;
    }
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

test "verifyProof accepts the matching did and transcript" {
    const allocator = std.testing.allocator;
    const key_pair = try identity.KeyPair.fromSeed([_]u8{0x88} ** 32);
    const did = try did_key.DidKey.fromKeyPair(key_pair).encode(allocator);
    defer allocator.free(did);

    const challenge = challenge_mod.Challenge.fromTranscript([_]u8{0x99} ** 32, "verify-proof", .server);
    var proof = try signChallenge(allocator, key_pair, did, challenge);
    defer proof.deinit(allocator);

    try verifyProof(allocator, challenge, proof);
}

test "verifyProof rejects a replay against a different transcript" {
    const allocator = std.testing.allocator;
    const key_pair = try identity.KeyPair.fromSeed([_]u8{0xaa} ** 32);
    const did = try did_key.DidKey.fromKeyPair(key_pair).encode(allocator);
    defer allocator.free(did);

    const original = challenge_mod.Challenge.fromTranscript([_]u8{0xbb} ** 32, "original", .client);
    const replayed = challenge_mod.Challenge.fromTranscript([_]u8{0xbb} ** 32, "replayed", .client);
    var proof = try signChallenge(allocator, key_pair, did, original);
    defer proof.deinit(allocator);

    try std.testing.expectError(error.InvalidSignature, verifyProof(allocator, replayed, proof));
}
