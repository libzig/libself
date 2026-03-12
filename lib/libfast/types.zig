const std = @import("std");
const challenge_mod = @import("../auth/challenge.zig");
const node_id_mod = @import("../node_id.zig");
const trust_policy = @import("../trust/policy.zig");

pub const TranscriptBinding = struct {
    hash: [32]u8,

    pub fn fromBytes(bytes: []const u8) TranscriptBinding {
        var hash: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(bytes, &hash, .{});
        return .{ .hash = hash };
    }

    pub fn fromTranscript(transcript: []const u8) TranscriptBinding {
        return fromBytes(transcript);
    }
};

pub const AuthContext = struct {
    subject: []const u8,
    role: challenge_mod.Role,
    binding: TranscriptBinding,

    pub fn challenge(self: AuthContext, nonce: [32]u8) challenge_mod.Challenge {
        return .{
            .nonce = nonce,
            .transcript_hash = self.binding.hash,
            .role = self.role,
        };
    }
};

pub const PeerIdentity = struct {
    allocator: std.mem.Allocator,
    did: []u8,
    node_id: node_id_mod.NodeId,
    trust: trust_policy.Decision,

    pub fn init(
        allocator: std.mem.Allocator,
        did: []const u8,
        public_key: [32]u8,
        trust: trust_policy.Decision,
    ) !PeerIdentity {
        return .{
            .allocator = allocator,
            .did = try allocator.dupe(u8, did),
            .node_id = node_id_mod.NodeId.fromPublicKey(public_key),
            .trust = trust,
        };
    }

    pub fn deinit(self: *PeerIdentity) void {
        self.allocator.free(self.did);
    }
};

test "transcript binding is deterministic" {
    const a = TranscriptBinding.fromTranscript("libfast-transcript");
    const b = TranscriptBinding.fromTranscript("libfast-transcript");
    const c = TranscriptBinding.fromTranscript("other-transcript");

    try std.testing.expectEqualSlices(u8, &a.hash, &b.hash);
    try std.testing.expect(!std.mem.eql(u8, &a.hash, &c.hash));
}

test "transcript binding from bytes matches transcript helper" {
    const transcript = "libfast-bytes";
    const from_bytes = TranscriptBinding.fromBytes(transcript);
    const from_transcript = TranscriptBinding.fromTranscript(transcript);

    try std.testing.expectEqualSlices(u8, &from_bytes.hash, &from_transcript.hash);
}

test "auth context derives a challenge from transcript binding" {
    const context = AuthContext{
        .subject = "peer-a",
        .role = .server,
        .binding = TranscriptBinding.fromTranscript("bound-transcript"),
    };
    const nonce = [_]u8{0x42} ** 32;
    const challenge = context.challenge(nonce);

    try std.testing.expectEqual(challenge_mod.Role.server, challenge.role);
    try std.testing.expectEqualSlices(u8, &nonce, &challenge.nonce);
    try std.testing.expectEqualSlices(u8, &context.binding.hash, &challenge.transcript_hash);
}

test "peer identity keeps did node id and trust decision" {
    const allocator = std.testing.allocator;
    var identity = try PeerIdentity.init(
        allocator,
        "did:key:zpeer",
        [_]u8{0x24} ** 32,
        .accepted_and_pinned,
    );
    defer identity.deinit();

    try std.testing.expectEqualStrings("did:key:zpeer", identity.did);
    try std.testing.expectEqual(trust_policy.Decision.accepted_and_pinned, identity.trust);
    try std.testing.expectEqual(@as(usize, 64), identity.node_id.toHex().len);
}
