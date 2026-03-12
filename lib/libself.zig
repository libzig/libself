pub const base58btc = @import("base58btc.zig");
pub const identity = @import("identity.zig");
pub const NodeId = @import("node_id.zig").NodeId;

pub fn hello() []const u8 {
    return "hello from libself";
}

test {
    try @import("std").testing.expectEqualStrings("hello from libself", hello());
}
