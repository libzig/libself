const libfast = @import("libfast");

pub fn state(connection: *libfast.QuicConnection) libfast.ConnectionState {
    return connection.getState();
}

pub fn negotiationSnapshot(connection: *const libfast.QuicConnection) ?libfast.NegotiationSnapshot {
    return connection.getNegotiationSnapshot();
}

test "libfast adapter reads public connection state" {
    var connection = try libfast.QuicConnection.init(
        @import("std").testing.allocator,
        libfast.QuicConfig.sshClient("example.com", ""),
    );
    defer connection.deinit();

    try @import("std").testing.expectEqual(libfast.ConnectionState.idle, state(&connection));
    try @import("std").testing.expect(negotiationSnapshot(&connection) == null);
}
