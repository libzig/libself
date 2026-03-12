const std = @import("std");
const libself = @import("libself");

pub fn main() !void {
    var store = libself.TrustStore.init(std.heap.page_allocator);
    defer store.deinit();

    const first = try store.evaluate(.tofu, "peer-a", "did:key:zfirst");
    const second = try store.evaluate(.tofu, "peer-a", "did:key:zfirst");
    const replacement = try store.evaluate(.tofu, "peer-a", "did:key:zother");

    std.debug.print("first: {any}\n", .{first});
    std.debug.print("second: {any}\n", .{second});
    std.debug.print("replacement: {any}\n", .{replacement});
}
