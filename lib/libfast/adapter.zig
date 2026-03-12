const std = @import("std");
const auth_challenge = @import("../auth/challenge.zig");
const libfast = @import("libfast");

pub fn state(connection: *const libfast.QuicConnection) libfast.ConnectionState {
    return connection.state;
}

pub fn negotiationSnapshot(
    connection: *const libfast.QuicConnection,
) @TypeOf(connection.getNegotiationSnapshot()) {
    return connection.getNegotiationSnapshot();
}

pub fn localRole(connection: *const libfast.QuicConnection) auth_challenge.Role {
    return switch (connection.config.role) {
        .client => .client,
        .server => .server,
    };
}

pub fn peerRole(connection: *const libfast.QuicConnection) auth_challenge.Role {
    return switch (localRole(connection)) {
        .client => .server,
        .server => .client,
    };
}

pub fn isHandshakeReady(connection: *const libfast.QuicConnection) bool {
    return connection.isHandshakeNegotiated();
}

pub fn requireHandshakeReady(connection: *const libfast.QuicConnection) error{HandshakeNotReady}!void {
    if (!isHandshakeReady(connection)) return error.HandshakeNotReady;
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

test "libfast adapter reads public connection state" {
    var connection = try libfast.QuicConnection.init(
        std.testing.allocator,
        libfast.QuicConfig.sshClient("example.com", ""),
    );
    defer connection.deinit();

    try std.testing.expectEqual(libfast.ConnectionState.idle, state(&connection));
    try std.testing.expect(negotiationSnapshot(&connection) == null);
}

test "libfast adapter maps local and peer roles" {
    var client = try libfast.QuicConnection.init(
        std.testing.allocator,
        libfast.QuicConfig.sshClient("example.com", ""),
    );
    defer client.deinit();

    var server = try libfast.QuicConnection.init(
        std.testing.allocator,
        libfast.QuicConfig.sshServer(""),
    );
    defer server.deinit();

    try std.testing.expectEqual(auth_challenge.Role.client, localRole(&client));
    try std.testing.expectEqual(auth_challenge.Role.server, peerRole(&client));
    try std.testing.expectEqual(auth_challenge.Role.server, localRole(&server));
    try std.testing.expectEqual(auth_challenge.Role.client, peerRole(&server));
}

test "libfast adapter reports handshake readiness" {
    var idle = try libfast.QuicConnection.init(
        std.testing.allocator,
        libfast.QuicConfig.sshClient("example.com", ""),
    );
    defer idle.deinit();

    try std.testing.expect(!isHandshakeReady(&idle));
    try std.testing.expectError(error.HandshakeNotReady, requireHandshakeReady(&idle));

    var negotiated = try initNegotiatedClient(std.testing.allocator, 0x11);
    defer negotiated.deinit();

    try std.testing.expect(isHandshakeReady(&negotiated));
    try requireHandshakeReady(&negotiated);
}
