const std = @import("std");
const libself = @import("libself");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer {
        const status = gpa.deinit();
        if (status == .leak) @panic("memory leak");
    }
    const allocator = gpa.allocator();

    const key_pair = try libself.identity.KeyPair.fromSeed([_]u8{0x20} ** 32);
    const did = try libself.DidKey.fromKeyPair(key_pair).encode(allocator);
    defer allocator.free(did);

    const challenge = libself.Challenge.fromTranscript([_]u8{0x30} ** 32, "auth-example", .client);
    var proof = try libself.auth.proof.signChallenge(allocator, key_pair, did, challenge);
    defer proof.deinit(allocator);

    try libself.auth.proof.verifyProof(allocator, challenge, proof);
    std.debug.print("verified: {s}\n", .{proof.did});
}
