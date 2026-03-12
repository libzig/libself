const std = @import("std");
const libself = @import("libself");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer {
        const status = gpa.deinit();
        if (status == .leak) @panic("memory leak");
    }
    const allocator = gpa.allocator();

    const key_pair = try libself.identity.KeyPair.fromSeed([_]u8{0x10} ** 32);
    const did = try libself.DidKey.fromKeyPair(key_pair).encode(allocator);
    defer allocator.free(did);

    var document = try libself.resolveDidKey(allocator, did);
    defer document.deinit(allocator);

    std.debug.print("did: {s}\n", .{document.id});
    std.debug.print("verification method: {s}\n", .{document.verification_method.id});
}
