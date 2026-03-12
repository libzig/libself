const std = @import("std");
const store_mod = @import("store.zig");

pub const Error = error{
    InvalidHeader,
    InvalidRecord,
    InvalidSubject,
    InvalidDid,
};

const header = "libself-trust-v1\n";

pub fn serializeAlloc(allocator: std.mem.Allocator, store: *const store_mod.Store) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);

    try out.appendSlice(allocator, header);

    var iterator = store.pins.iterator();
    while (iterator.next()) |entry| {
        try validateField(entry.key_ptr.*, error.InvalidSubject);
        try validateField(entry.value_ptr.*, error.InvalidDid);

        try out.writer(allocator).print("{s}\t{s}\n", .{
            entry.key_ptr.*,
            entry.value_ptr.*,
        });
    }

    return out.toOwnedSlice(allocator);
}

pub fn deserializeInto(store: *store_mod.Store, bytes: []const u8) !void {
    if (!std.mem.startsWith(u8, bytes, header)) {
        return error.InvalidHeader;
    }

    var lines = std.mem.tokenizeScalar(u8, bytes[header.len..], '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;

        const split_at = std.mem.indexOfScalar(u8, line, '\t') orelse return error.InvalidRecord;
        const subject = line[0..split_at];
        const did = line[split_at + 1 ..];

        try validateField(subject, error.InvalidSubject);
        try validateField(did, error.InvalidDid);
        try store.pin(subject, did);
    }
}

fn validateField(field: []const u8, comptime err: anyerror) err!void {
    if (field.len == 0) return err;
    if (std.mem.indexOfScalar(u8, field, '\t') != null) return err;
    if (std.mem.indexOfScalar(u8, field, '\n') != null) return err;
}

test "trust file format serializes and deserializes store entries" {
    const allocator = std.testing.allocator;
    var original = store_mod.Store.init(allocator);
    defer original.deinit();
    try original.pin("peer-a", "did:key:zfirst");
    try original.pin("peer-b", "did:key:zsecond");

    const encoded = try serializeAlloc(allocator, &original);
    defer allocator.free(encoded);

    var decoded = store_mod.Store.init(allocator);
    defer decoded.deinit();
    try deserializeInto(&decoded, encoded);

    try std.testing.expectEqualStrings("did:key:zfirst", decoded.getPinnedDid("peer-a").?);
    try std.testing.expectEqualStrings("did:key:zsecond", decoded.getPinnedDid("peer-b").?);
}

test "trust file format rejects invalid header" {
    var store = store_mod.Store.init(std.testing.allocator);
    defer store.deinit();

    try std.testing.expectError(
        error.InvalidHeader,
        deserializeInto(&store, "wrong-header\npeer-a\tdid:key:zfirst\n"),
    );
}

test "trust file format rejects invalid records" {
    var store = store_mod.Store.init(std.testing.allocator);
    defer store.deinit();

    try std.testing.expectError(
        error.InvalidRecord,
        deserializeInto(&store, header ++ "peer-a did:key:zfirst\n"),
    );
}
