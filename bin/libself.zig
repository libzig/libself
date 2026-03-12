const std = @import("std");
const libself = @import("libself");

pub fn main() !void {
    std.debug.print("{s}\n", .{libself.hello()});
}
