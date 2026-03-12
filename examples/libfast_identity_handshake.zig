const std = @import("std");
const libfast = @import("libfast");
const libself = @import("libself");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer {
        const status = gpa.deinit();
        if (status == .leak) @panic("memory leak");
    }
    const allocator = gpa.allocator();

    var connection = try initNegotiatedClient(allocator, 0xa1);
    defer connection.deinit();
    var attached = try libself.LibfastAuthenticatedConnection.init(allocator, &connection, "peer-a");
    defer attached.deinit();

    var peer_local = try libself.LibfastLocalIdentity.fromSeed(allocator, [_]u8{0xa2} ** 32);
    defer peer_local.deinit();

    const challenge_message = try attached.newPeerChallenge([_]u8{0xa3} ** 32);
    const peer_context = try attached.peerContext();
    var proof_message = try libself.libfast.session.signProofMessage(
        allocator,
        peer_local.key_pair,
        peer_local.did,
        peer_context,
        challenge_message,
    );
    defer proof_message.deinit(allocator);

    var store = libself.TrustStore.init(allocator);
    defer store.deinit();
    const decision = try attached.verifyPeerProof(.tofu, &store, challenge_message, proof_message);

    std.debug.print("authenticated did: {s}\n", .{attached.peerDid().?});
    std.debug.print("trust: {any}\n", .{decision});
    std.debug.print("node id: {s}\n", .{attached.peerNodeId().?.toHex()});
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
