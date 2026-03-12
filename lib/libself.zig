pub const base58btc = @import("base58btc.zig");
pub const identity = @import("identity.zig");
pub const NodeId = @import("node_id.zig").NodeId;
pub const did = struct {
    pub const document = @import("did/document.zig");
    pub const key = @import("did/key.zig");
    pub const resolver = @import("did/resolver.zig");
};
pub const auth = struct {
    pub const challenge = @import("auth/challenge.zig");
    pub const proof = @import("auth/proof.zig");
};
pub const DidKey = did.key.DidKey;
pub const Document = did.document.Document;

pub fn hello() []const u8 {
    return "hello from libself";
}

test {
    try @import("std").testing.expectEqualStrings("hello from libself", hello());
}
