const std = @import("std");

pub const domain_separator = "libself-auth-v1";

pub const Role = enum(u8) {
    client = 0,
    server = 1,
};

pub const Challenge = struct {
    nonce: [32]u8,
    transcript_hash: [32]u8,
    role: Role,

    pub fn generate(transcript: []const u8, role: Role) Challenge {
        var nonce: [32]u8 = undefined;
        std.crypto.random.bytes(&nonce);
        return fromTranscript(nonce, transcript, role);
    }

    pub fn fromTranscript(nonce: [32]u8, transcript: []const u8, role: Role) Challenge {
        var transcript_hash: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(transcript, &transcript_hash, .{});
        return .{
            .nonce = nonce,
            .transcript_hash = transcript_hash,
            .role = role,
        };
    }

    pub fn contextBytes(self: Challenge) [65]u8 {
        var out: [65]u8 = undefined;
        out[0] = @intFromEnum(self.role);
        out[1..33].* = self.nonce;
        out[33..65].* = self.transcript_hash;
        return out;
    }

    pub fn payloadAlloc(self: Challenge, allocator: std.mem.Allocator, did: []const u8) ![]u8 {
        const context = self.contextBytes();
        return std.fmt.allocPrint(allocator, "{s}{s}{s}", .{ domain_separator, context, did });
    }
};

test "challenge hashes transcript deterministically" {
    const nonce = [_]u8{0x33} ** 32;
    const a = Challenge.fromTranscript(nonce, "transcript-a", .client);
    const b = Challenge.fromTranscript(nonce, "transcript-a", .client);

    try std.testing.expectEqualSlices(u8, &a.contextBytes(), &b.contextBytes());
}

test "challenge payload changes with transcript or role" {
    const allocator = std.testing.allocator;
    const nonce = [_]u8{0x44} ** 32;
    const client = Challenge.fromTranscript(nonce, "same-transcript", .client);
    const server = Challenge.fromTranscript(nonce, "same-transcript", .server);
    const other = Challenge.fromTranscript(nonce, "other-transcript", .client);

    const client_payload = try client.payloadAlloc(allocator, "did:key:zexample");
    defer allocator.free(client_payload);

    const server_payload = try server.payloadAlloc(allocator, "did:key:zexample");
    defer allocator.free(server_payload);

    const other_payload = try other.payloadAlloc(allocator, "did:key:zexample");
    defer allocator.free(other_payload);

    try std.testing.expect(!std.mem.eql(u8, client_payload, server_payload));
    try std.testing.expect(!std.mem.eql(u8, client_payload, other_payload));
}
