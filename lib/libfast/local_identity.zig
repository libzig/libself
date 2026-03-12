const std = @import("std");
const did_key = @import("../did/key.zig");
const identity = @import("../identity.zig");

pub const LocalIdentity = struct {
    allocator: std.mem.Allocator,
    key_pair: identity.KeyPair,
    did: []u8,

    pub fn fromKeyPair(allocator: std.mem.Allocator, key_pair: identity.KeyPair) !LocalIdentity {
        return .{
            .allocator = allocator,
            .key_pair = key_pair,
            .did = try did_key.DidKey.fromKeyPair(key_pair).encode(allocator),
        };
    }

    pub fn fromSeed(allocator: std.mem.Allocator, seed: identity.Seed) !LocalIdentity {
        return fromKeyPair(allocator, try identity.KeyPair.fromSeed(seed));
    }

    pub fn generate(allocator: std.mem.Allocator, random: std.Random) !LocalIdentity {
        return fromKeyPair(allocator, identity.KeyPair.generate(random));
    }

    pub fn deinit(self: *LocalIdentity) void {
        self.allocator.free(self.did);
    }
};

test "local identity derives did from key pair" {
    const allocator = std.testing.allocator;
    const key_pair = try identity.KeyPair.fromSeed([_]u8{0x11} ** 32);
    var local = try LocalIdentity.fromKeyPair(allocator, key_pair);
    defer local.deinit();

    const expected_did = try did_key.DidKey.fromKeyPair(key_pair).encode(allocator);
    defer allocator.free(expected_did);

    try std.testing.expectEqualStrings(expected_did, local.did);
    try std.testing.expectEqualSlices(u8, &key_pair.public_key, &local.key_pair.public_key);
}

test "local identity from seed is deterministic" {
    const allocator = std.testing.allocator;
    var first = try LocalIdentity.fromSeed(allocator, [_]u8{0x22} ** 32);
    defer first.deinit();
    var second = try LocalIdentity.fromSeed(allocator, [_]u8{0x22} ** 32);
    defer second.deinit();

    try std.testing.expectEqualStrings(first.did, second.did);
    try std.testing.expectEqualSlices(u8, &first.key_pair.public_key, &second.key_pair.public_key);
}
