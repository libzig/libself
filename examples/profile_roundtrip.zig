const std = @import("std");
const libself = @import("libself");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer {
        const status = gpa.deinit();
        if (status == .leak) @panic("memory leak");
    }
    const allocator = gpa.allocator();

    var profile = try libself.Profile.init(allocator, "did:key:zprofile");
    defer profile.deinit();
    try profile.setDisplayName("alice");
    try profile.setTransportHint("quic");
    try profile.setMetadata("region", "eu");

    const json = try profile.toJsonAlloc(allocator);
    defer allocator.free(json);

    var decoded = try libself.Profile.fromJson(allocator, json);
    defer decoded.deinit();

    std.debug.print("profile did: {s}\n", .{decoded.did});
    std.debug.print("display name: {s}\n", .{decoded.display_name.?});
    std.debug.print("region: {s}\n", .{decoded.getMetadata("region").?});
}
