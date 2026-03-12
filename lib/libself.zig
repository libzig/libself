pub const base58btc = @import("base58btc.zig");
pub const identity = @import("identity.zig");
pub const NodeId = @import("node_id.zig").NodeId;
pub const did = struct {
    pub const key = @import("did/key.zig");
};
pub const DidKey = did.key.DidKey;

pub fn hello() []const u8 {
    return "hello from libself";
}

test {
    try @import("std").testing.expectEqualStrings("hello from libself", hello());
}
