const std = @import("std");
const auth_challenge = @import("../auth/challenge.zig");
const auth_proof = @import("../auth/proof.zig");

pub const Error = error{
    InvalidLength,
    InvalidRole,
    TruncatedDid,
};

pub const ChallengeMessage = struct {
    role: auth_challenge.Role,
    nonce: [32]u8,

    pub fn encode(self: ChallengeMessage) [33]u8 {
        var out: [33]u8 = undefined;
        out[0] = @intFromEnum(self.role);
        out[1..].* = self.nonce;
        return out;
    }

    pub fn decode(bytes: []const u8) Error!ChallengeMessage {
        if (bytes.len != 33) return error.InvalidLength;

        const role = std.meta.intToEnum(auth_challenge.Role, bytes[0]) catch {
            return error.InvalidRole;
        };

        return .{
            .role = role,
            .nonce = bytes[1..33].*,
        };
    }
};

pub const ProofMessage = struct {
    did: []u8,
    signature: [64]u8,

    pub fn fromProof(allocator: std.mem.Allocator, proof: auth_proof.Proof) !ProofMessage {
        return .{
            .did = try allocator.dupe(u8, proof.did),
            .signature = proof.signature,
        };
    }

    pub fn toProof(self: ProofMessage, allocator: std.mem.Allocator) !auth_proof.Proof {
        return .{
            .did = try allocator.dupe(u8, self.did),
            .signature = self.signature,
        };
    }

    pub fn deinit(self: *ProofMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.did);
    }

    pub fn encodeAlloc(self: ProofMessage, allocator: std.mem.Allocator) ![]u8 {
        if (self.did.len > std.math.maxInt(u16)) return error.InvalidLength;

        const out = try allocator.alloc(u8, 2 + self.did.len + self.signature.len);
        std.mem.writeInt(u16, out[0..2], @intCast(self.did.len), .big);
        @memcpy(out[2 .. 2 + self.did.len], self.did);
        @memcpy(out[2 + self.did.len ..], &self.signature);
        return out;
    }

    pub fn decodeAlloc(allocator: std.mem.Allocator, bytes: []const u8) !ProofMessage {
        if (bytes.len < 2 + 64) return error.InvalidLength;

        const did_len = std.mem.readInt(u16, bytes[0..2], .big);
        if (bytes.len != 2 + did_len + 64) return error.TruncatedDid;

        return .{
            .did = try allocator.dupe(u8, bytes[2 .. 2 + did_len]),
            .signature = bytes[2 + did_len ..][0..64].*,
        };
    }
};

test "challenge message roundtrip" {
    const message = ChallengeMessage{
        .role = .client,
        .nonce = [_]u8{0x11} ** 32,
    };

    const encoded = message.encode();
    const decoded = try ChallengeMessage.decode(&encoded);

    try std.testing.expectEqual(auth_challenge.Role.client, decoded.role);
    try std.testing.expectEqualSlices(u8, &message.nonce, &decoded.nonce);
}

test "proof message roundtrip" {
    const allocator = std.testing.allocator;
    var original = ProofMessage{
        .did = try allocator.dupe(u8, "did:key:zproof"),
        .signature = [_]u8{0x22} ** 64,
    };
    defer original.deinit(allocator);

    const encoded = try original.encodeAlloc(allocator);
    defer allocator.free(encoded);

    var decoded = try ProofMessage.decodeAlloc(allocator, encoded);
    defer decoded.deinit(allocator);

    try std.testing.expectEqualStrings(original.did, decoded.did);
    try std.testing.expectEqualSlices(u8, &original.signature, &decoded.signature);
}

test "proof message rejects truncated payloads" {
    try std.testing.expectError(
        error.InvalidLength,
        ProofMessage.decodeAlloc(std.testing.allocator, &[_]u8{ 0x00, 0x01, 0xff }),
    );
}
