const std = @import("std");
const document = @import("document.zig");
const identity = @import("../identity.zig");
const key = @import("key.zig");

pub fn resolveDidKey(allocator: std.mem.Allocator, did: []const u8) !document.Document {
    const parsed = try key.DidKey.parse(allocator, did);
    const method_specific_id = try parsed.methodSpecificId(allocator);
    errdefer allocator.free(method_specific_id);

    const did_id = try parsed.encode(allocator);
    errdefer allocator.free(did_id);

    const verification_method_id = try std.fmt.allocPrint(allocator, "{s}#{s}", .{ did_id, method_specific_id });
    errdefer allocator.free(verification_method_id);

    return .{
        .id = did_id,
        .verification_method = .{
            .id = verification_method_id,
            .controller = try allocator.dupe(u8, did_id),
            .type_name = key.verification_type,
            .public_key_multibase = method_specific_id,
        },
    };
}

test "resolver derives a local did document" {
    const allocator = std.testing.allocator;
    const key_pair = try identity.KeyPair.fromSeed([_]u8{0x44} ** 32);
    const did = try key.DidKey.fromKeyPair(key_pair).encode(allocator);
    defer allocator.free(did);

    var resolved = try resolveDidKey(allocator, did);
    defer resolved.deinit(allocator);

    try std.testing.expectEqualStrings(did, resolved.id);
    try std.testing.expectEqualStrings(did, resolved.verification_method.controller);
    try std.testing.expect(std.mem.startsWith(u8, resolved.verification_method.id, did));
    try std.testing.expectEqualStrings(key.verification_type, resolved.verification_method.type_name);
}

test "resolver is stable for the same did:key" {
    const allocator = std.testing.allocator;
    const key_pair = try identity.KeyPair.fromSeed([_]u8{0x55} ** 32);
    const did = try key.DidKey.fromKeyPair(key_pair).encode(allocator);
    defer allocator.free(did);

    var a = try resolveDidKey(allocator, did);
    defer a.deinit(allocator);

    var b = try resolveDidKey(allocator, did);
    defer b.deinit(allocator);

    try std.testing.expectEqualStrings(a.id, b.id);
    try std.testing.expectEqualStrings(a.verification_method.id, b.verification_method.id);
    try std.testing.expectEqualStrings(a.verification_method.public_key_multibase, b.verification_method.public_key_multibase);
}
