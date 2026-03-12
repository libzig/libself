const std = @import("std");
const policy = @import("policy.zig");

pub const Store = struct {
    allocator: std.mem.Allocator,
    pins: std.StringHashMap([]u8),

    pub fn init(allocator: std.mem.Allocator) Store {
        return .{
            .allocator = allocator,
            .pins = std.StringHashMap([]u8).init(allocator),
        };
    }

    pub fn deinit(self: *Store) void {
        var iterator = self.pins.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.pins.deinit();
    }

    pub fn pin(self: *Store, subject: []const u8, did: []const u8) !void {
        const owned_subject = try self.allocator.dupe(u8, subject);
        errdefer self.allocator.free(owned_subject);

        const owned_did = try self.allocator.dupe(u8, did);
        errdefer self.allocator.free(owned_did);

        const entry = try self.pins.getOrPut(owned_subject);
        if (entry.found_existing) {
            self.allocator.free(owned_subject);
            self.allocator.free(entry.value_ptr.*);
        }

        entry.value_ptr.* = owned_did;
    }

    pub fn evaluate(
        self: *Store,
        mode: policy.Mode,
        subject: []const u8,
        did: []const u8,
    ) !policy.Decision {
        switch (mode) {
            .accept_any => return .accepted,
            .pinned => {
                const pinned_did = self.pins.get(subject) orelse return .rejected;
                return if (std.mem.eql(u8, pinned_did, did)) .accepted else .rejected;
            },
            .tofu => {
                if (self.pins.get(subject)) |pinned_did| {
                    return if (std.mem.eql(u8, pinned_did, did)) .accepted else .rejected;
                }

                try self.pin(subject, did);
                return .accepted_and_pinned;
            },
        }
    }
};

test "accept_any mode accepts any did" {
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    try std.testing.expectEqual(
        policy.Decision.accepted,
        try store.evaluate(.accept_any, "peer-a", "did:key:za"),
    );
}

test "tofu pins first contact and rejects replacement" {
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    try std.testing.expectEqual(
        policy.Decision.accepted_and_pinned,
        try store.evaluate(.tofu, "peer-a", "did:key:zfirst"),
    );
    try std.testing.expectEqual(
        policy.Decision.accepted,
        try store.evaluate(.tofu, "peer-a", "did:key:zfirst"),
    );
    try std.testing.expectEqual(
        policy.Decision.rejected,
        try store.evaluate(.tofu, "peer-a", "did:key:zother"),
    );
}

test "pinned mode only accepts pre-pinned entries" {
    var store = Store.init(std.testing.allocator);
    defer store.deinit();
    try store.pin("peer-a", "did:key:zfirst");

    try std.testing.expectEqual(
        policy.Decision.accepted,
        try store.evaluate(.pinned, "peer-a", "did:key:zfirst"),
    );
    try std.testing.expectEqual(
        policy.Decision.rejected,
        try store.evaluate(.pinned, "peer-a", "did:key:zother"),
    );
    try std.testing.expectEqual(
        policy.Decision.rejected,
        try store.evaluate(.pinned, "peer-b", "did:key:zfirst"),
    );
}
