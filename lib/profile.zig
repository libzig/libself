const std = @import("std");

pub const Profile = struct {
    allocator: std.mem.Allocator,
    did: []u8,
    display_name: ?[]u8 = null,
    transport_hint: ?[]u8 = null,
    local_label: ?[]u8 = null,

    pub fn init(allocator: std.mem.Allocator, did: []const u8) !Profile {
        return .{
            .allocator = allocator,
            .did = try allocator.dupe(u8, did),
        };
    }

    pub fn deinit(self: *Profile) void {
        self.allocator.free(self.did);
        freeOptional(self.allocator, &self.display_name);
        freeOptional(self.allocator, &self.transport_hint);
        freeOptional(self.allocator, &self.local_label);
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
