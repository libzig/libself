const std = @import("std");

pub const byte_len = 32;

pub const NodeId = struct {
    bytes: [byte_len]u8,

    pub fn fromPublicKey(public_key: [32]u8) NodeId {
        var digest: [byte_len]u8 = undefined;
        std.crypto.hash.Blake3.hash(&public_key, &digest, .{});
        return .{ .bytes = digest };
    }

    pub fn toBytes(self: NodeId) [byte_len]u8 {
        return self.bytes;
    }

    pub fn toHex(self: NodeId) [byte_len * 2]u8 {
        return std.fmt.bytesToHex(self.bytes, .lower);
    }
};

test "node id is deterministic for the same public key" {
    const public_key = [_]u8{0x5a} ** 32;

    const a = NodeId.fromPublicKey(public_key);
    const b = NodeId.fromPublicKey(public_key);

    try std.testing.expectEqualSlices(u8, &a.toBytes(), &b.toBytes());
    try std.testing.expectEqual(@as(usize, 64), a.toHex().len);
}

test "node ids differ for different public keys" {
    const a = NodeId.fromPublicKey([_]u8{0x10} ** 32);
    const b = NodeId.fromPublicKey([_]u8{0x20} ** 32);

    try std.testing.expect(!std.mem.eql(u8, &a.toBytes(), &b.toBytes()));
}
