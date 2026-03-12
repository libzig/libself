const std = @import("std");
const auth_challenge = @import("../auth/challenge.zig");
const libfast = @import("libfast");

pub fn state(connection: *libfast.QuicConnection) libfast.ConnectionState {
    return connection.getState();
}

pub fn negotiationSnapshot(connection: *const libfast.QuicConnection) ?libfast.NegotiationSnapshot {
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
