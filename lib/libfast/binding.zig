const std = @import("std");
const adapter = @import("adapter.zig");
const libfast = @import("libfast");
const types = @import("types.zig");

pub const Error = error{
    HandshakeNotReady,
    MissingInternalConnection,
} || std.mem.Allocator.Error;

pub fn materialAlloc(allocator: std.mem.Allocator, connection: *const libfast.QuicConnection) Error![]u8 {
    try adapter.requireHandshakeReady(connection);

    const internal = connection.internal_conn orelse return error.MissingInternalConnection;
    const snapshot = connection.getNegotiationSnapshot() orelse return error.MissingInternalConnection;

    var out: std.ArrayList(u8) = .{};
    errdefer out.deinit(allocator);

    try out.appendSlice(allocator, "libself-libfast-binding-v1");
    try out.append(allocator, @intFromEnum(adapter.localRole(connection)));
    try out.append(allocator, @intFromEnum(adapter.peerRole(connection)));
    try out.append(allocator, @intFromEnum(connection.state));
    try out.append(allocator, @intFromEnum(snapshot.mode));
    try out.append(allocator, @intFromBool(snapshot.is_established));
    try appendCid(&out, allocator, internal.local_conn_id.slice());
    try appendCid(&out, allocator, internal.remote_conn_id.slice());
    try appendBytes16(&out, allocator, snapshot.alpn orelse "");
    try appendU64(&out, allocator, snapshot.peer_max_idle_timeout);
    try appendU64(&out, allocator, snapshot.peer_max_udp_payload_size);
    try appendU64(&out, allocator, snapshot.peer_initial_max_data);
    try appendU64(&out, allocator, snapshot.peer_initial_max_streams_bidi);
    try appendU64(&out, allocator, snapshot.peer_initial_max_streams_uni);

    const peer_cid_count = connection.getPeerConnectionIdCount();
    try appendU16(&out, allocator, @intCast(peer_cid_count));
    for (0..peer_cid_count) |index| {
        const info = connection.getPeerConnectionIdInfo(index).?;
        try appendU64(&out, allocator, info.sequence_number);
        try appendCid(&out, allocator, info.connection_id[0..info.connection_id_len]);
        try out.appendSlice(allocator, &info.stateless_reset_token);
    }

    try appendBytes16(&out, allocator, connection.getLatestNewToken() orelse "");
    try appendCid(&out, allocator, connection.getRetrySourceConnectionId() orelse "");
    try appendBytes16(&out, allocator, connection.getRetryToken() orelse "");

    return out.toOwnedSlice(allocator);
}

pub fn transcriptBinding(
    allocator: std.mem.Allocator,
    connection: *const libfast.QuicConnection,
) Error!types.TranscriptBinding {
    const material = try materialAlloc(allocator, connection);
    defer allocator.free(material);
    return types.TranscriptBinding.fromBytes(material);
}

fn appendU16(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u16) !void {
    var bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &bytes, value, .big);
    try out.appendSlice(allocator, &bytes);
}

fn appendU64(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u64) !void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .big);
    try out.appendSlice(allocator, &bytes);
}

fn appendCid(out: *std.ArrayList(u8), allocator: std.mem.Allocator, bytes: []const u8) !void {
    try out.append(allocator, @intCast(bytes.len));
    try out.appendSlice(allocator, bytes);
}

fn appendBytes16(out: *std.ArrayList(u8), allocator: std.mem.Allocator, bytes: []const u8) !void {
    try appendU16(out, allocator, @intCast(bytes.len));
    try out.appendSlice(allocator, bytes);
}

fn initNegotiatedClient(allocator: std.mem.Allocator, seed: u8) !libfast.QuicConnection {
    var connection = try libfast.QuicConnection.init(
        allocator,
        libfast.QuicConfig.sshClient("example.com", ""),
    );
    errdefer connection.deinit();

    const internal = try allocator.create(libfast.connection.Connection);
    errdefer allocator.destroy(internal);

    const local_cid = try libfast.ConnectionId.init(&([_]u8{seed} ** 8));
    const remote_cid = try libfast.ConnectionId.init(&([_]u8{seed +% 1} ** 8));
    internal.* = try libfast.connection.Connection.initClient(allocator, .ssh, local_cid, remote_cid);
    connection.internal_conn = internal;

    const encoded_params = try libfast.transport_params.TransportParams.defaultServer().encode(allocator);
    defer allocator.free(encoded_params);

    try connection.applyPeerTransportParams(encoded_params);
    connection.state = .established;
    return connection;
}

test "binding material rejects unnegotiated connections" {
    var connection = try libfast.QuicConnection.init(
        std.testing.allocator,
        libfast.QuicConfig.sshClient("example.com", ""),
    );
    defer connection.deinit();

    try std.testing.expectError(
        error.HandshakeNotReady,
        materialAlloc(std.testing.allocator, &connection),
    );
}

test "binding material is deterministic for the same connection state" {
    const allocator = std.testing.allocator;
    var connection = try initNegotiatedClient(allocator, 0x21);
    defer connection.deinit();

    const first = try materialAlloc(allocator, &connection);
    defer allocator.free(first);
    const second = try materialAlloc(allocator, &connection);
    defer allocator.free(second);

    try std.testing.expectEqualStrings(first, second);
}

test "binding material changes across different negotiated connections" {
    const allocator = std.testing.allocator;
    var first = try initNegotiatedClient(allocator, 0x31);
    defer first.deinit();
    var second = try initNegotiatedClient(allocator, 0x41);
    defer second.deinit();

    const first_material = try materialAlloc(allocator, &first);
    defer allocator.free(first_material);
    const second_material = try materialAlloc(allocator, &second);
    defer allocator.free(second_material);

    try std.testing.expect(!std.mem.eql(u8, first_material, second_material));
}

test "binding hash is stable for the same negotiated connection" {
    const allocator = std.testing.allocator;
    var connection = try initNegotiatedClient(allocator, 0x51);
    defer connection.deinit();

    const first = try transcriptBinding(allocator, &connection);
    const second = try transcriptBinding(allocator, &connection);

    try std.testing.expectEqualSlices(u8, &first.hash, &second.hash);
}

test "binding hash changes across different negotiated connections" {
    const allocator = std.testing.allocator;
    var first = try initNegotiatedClient(allocator, 0x61);
    defer first.deinit();
    var second = try initNegotiatedClient(allocator, 0x71);
    defer second.deinit();

    const first_binding = try transcriptBinding(allocator, &first);
    const second_binding = try transcriptBinding(allocator, &second);

    try std.testing.expect(!std.mem.eql(u8, &first_binding.hash, &second_binding.hash));
}
