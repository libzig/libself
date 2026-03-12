const std = @import("std");

pub const Profile = struct {
    allocator: std.mem.Allocator,
    did: []u8,
    display_name: ?[]u8 = null,
    transport_hint: ?[]u8 = null,
    local_label: ?[]u8 = null,
    metadata: std.StringHashMap([]u8),

    pub fn init(allocator: std.mem.Allocator, did: []const u8) !Profile {
        return .{
            .allocator = allocator,
            .did = try allocator.dupe(u8, did),
            .metadata = std.StringHashMap([]u8).init(allocator),
        };
    }

    pub fn deinit(self: *Profile) void {
        self.allocator.free(self.did);
        freeOptional(self.allocator, &self.display_name);
        freeOptional(self.allocator, &self.transport_hint);
        freeOptional(self.allocator, &self.local_label);
        var iterator = self.metadata.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.metadata.deinit();
    }

    pub fn setDisplayName(self: *Profile, value: ?[]const u8) !void {
        try replaceOptional(self.allocator, &self.display_name, value);
    }

    pub fn setTransportHint(self: *Profile, value: ?[]const u8) !void {
        try replaceOptional(self.allocator, &self.transport_hint, value);
    }

    pub fn setLocalLabel(self: *Profile, value: ?[]const u8) !void {
        try replaceOptional(self.allocator, &self.local_label, value);
    }

    pub fn setMetadata(self: *Profile, key: []const u8, value: []const u8) !void {
        const owned_key = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(owned_key);

        const owned_value = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(owned_value);

        const entry = try self.metadata.getOrPut(owned_key);
        if (entry.found_existing) {
            self.allocator.free(owned_key);
            self.allocator.free(entry.value_ptr.*);
        }

        entry.value_ptr.* = owned_value;
    }

    pub fn getMetadata(self: *const Profile, key: []const u8) ?[]const u8 {
        return self.metadata.get(key);
    }

    pub fn removeMetadata(self: *Profile, key: []const u8) bool {
        const removed = self.metadata.fetchRemove(key) orelse return false;
        self.allocator.free(removed.key);
        self.allocator.free(removed.value);
        return true;
    }
};

fn replaceOptional(
    allocator: std.mem.Allocator,
    field: *?[]u8,
    value: ?[]const u8,
) !void {
    freeOptional(allocator, field);
    if (value) |bytes| {
        field.* = try allocator.dupe(u8, bytes);
    }
}

fn freeOptional(allocator: std.mem.Allocator, field: *?[]u8) void {
    if (field.*) |bytes| {
        allocator.free(bytes);
        field.* = null;
    }
}

test "profile init stores did and empty optional fields" {
    var profile = try Profile.init(std.testing.allocator, "did:key:zprofile");
    defer profile.deinit();

    try std.testing.expectEqualStrings("did:key:zprofile", profile.did);
    try std.testing.expect(profile.display_name == null);
    try std.testing.expect(profile.transport_hint == null);
    try std.testing.expect(profile.local_label == null);
    try std.testing.expectEqual(@as(u32, 0), profile.metadata.count());
}

test "profile setters replace core fields" {
    var profile = try Profile.init(std.testing.allocator, "did:key:zprofile");
    defer profile.deinit();

    try profile.setDisplayName("alice");
    try profile.setTransportHint("quic");
    try profile.setLocalLabel("laptop");

    try std.testing.expectEqualStrings("alice", profile.display_name.?);
    try std.testing.expectEqualStrings("quic", profile.transport_hint.?);
    try std.testing.expectEqualStrings("laptop", profile.local_label.?);

    try profile.setDisplayName("alice-2");
    try profile.setLocalLabel(null);

    try std.testing.expectEqualStrings("alice-2", profile.display_name.?);
    try std.testing.expect(profile.local_label == null);
}

test "profile metadata helpers set replace and remove keys" {
    var profile = try Profile.init(std.testing.allocator, "did:key:zprofile");
    defer profile.deinit();

    try profile.setMetadata("region", "eu");
    try profile.setMetadata("device", "laptop");
    try std.testing.expectEqualStrings("eu", profile.getMetadata("region").?);
    try std.testing.expectEqualStrings("laptop", profile.getMetadata("device").?);

    try profile.setMetadata("region", "us");
    try std.testing.expectEqualStrings("us", profile.getMetadata("region").?);
    try std.testing.expect(profile.removeMetadata("region"));
    try std.testing.expect(profile.getMetadata("region") == null);
    try std.testing.expect(!profile.removeMetadata("region"));
}
