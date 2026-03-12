const std = @import("std");
const base58btc = @import("../base58btc.zig");
const identity = @import("../identity.zig");

pub const did_prefix = "did:key:";
pub const multicodec_ed25519_pub = [_]u8{ 0xed, 0x01 };

pub const ParseError = error{
    InvalidDidPrefix,
    UnsupportedMultibase,
    InvalidBase58,
    InvalidMulticodec,
    InvalidPublicKeyLength,
};

pub const DidKey = struct {
    public_key: identity.PublicKey,

    pub fn fromPublicKey(public_key: identity.PublicKey) DidKey {
        return .{ .public_key = public_key };
    }

    pub fn fromKeyPair(key_pair: identity.KeyPair) DidKey {
        return fromPublicKey(key_pair.public_key);
    }

    pub fn methodSpecificId(self: DidKey, allocator: std.mem.Allocator) ![]u8 {
        var payload: [multicodec_ed25519_pub.len + identity.PublicKey.len]u8 = undefined;
        payload[0..multicodec_ed25519_pub.len].* = multicodec_ed25519_pub;
        payload[multicodec_ed25519_pub.len..].* = self.public_key;

        const encoded = try base58btc.encodeAlloc(allocator, &payload);
        defer allocator.free(encoded);

        return std.fmt.allocPrint(allocator, "z{s}", .{encoded});
    }

    pub fn encode(self: DidKey, allocator: std.mem.Allocator) ![]u8 {
        const id = try self.methodSpecificId(allocator);
        defer allocator.free(id);

        return std.fmt.allocPrint(allocator, "{s}{s}", .{ did_prefix, id });
    }

    pub fn parse(allocator: std.mem.Allocator, did: []const u8) ParseError!DidKey {
        if (!std.mem.startsWith(u8, did, did_prefix)) {
            return error.InvalidDidPrefix;
        }

        const method_specific_id = did[did_prefix.len..];
        if (method_specific_id.len == 0 or method_specific_id[0] != 'z') {
            return error.UnsupportedMultibase;
        }

        const decoded = base58btc.decodeAlloc(allocator, method_specific_id[1..]) catch {
            return error.InvalidBase58;
        };
        defer allocator.free(decoded);

        if (decoded.len != multicodec_ed25519_pub.len + identity.PublicKey.len) {
            return error.InvalidPublicKeyLength;
        }

        if (!std.mem.eql(u8, decoded[0..multicodec_ed25519_pub.len], &multicodec_ed25519_pub)) {
            return error.InvalidMulticodec;
        }

        return .{
            .public_key = decoded[multicodec_ed25519_pub.len..].*,
        };
    }
};

test "did:key encode and parse roundtrip" {
    const allocator = std.testing.allocator;
    const key_pair = try identity.KeyPair.fromSeed([_]u8{0x22} ** 32);

    const did_key = DidKey.fromKeyPair(key_pair);
    const encoded = try did_key.encode(allocator);
    defer allocator.free(encoded);

    const parsed = try DidKey.parse(allocator, encoded);

    try std.testing.expectEqualSlices(u8, &did_key.public_key, &parsed.public_key);
}

test "did:key rejects invalid prefix" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(
        error.InvalidDidPrefix,
        DidKey.parse(allocator, "did:web:example.com"),
    );
}
