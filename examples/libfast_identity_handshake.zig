const std = @import("std");
const libself = @import("libself");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer {
        const status = gpa.deinit();
        if (status == .leak) @panic("memory leak");
    }
    const allocator = gpa.allocator();

    const key_pair = try libself.identity.KeyPair.fromSeed([_]u8{0xa1} ** 32);
    const did = try libself.DidKey.fromKeyPair(key_pair).encode(allocator);
    defer allocator.free(did);

    const context = libself.LibfastAuthContext{
        .subject = "peer-a",
        .role = .server,
        .binding = libself.LibfastTranscriptBinding.fromTranscript("libfast-example"),
    };
    const challenge_message = libself.libfast.session.newChallengeMessage(context, [_]u8{0xa2} ** 32);
    var proof_message = try libself.libfast.session.signProofMessage(
        allocator,
        key_pair,
        did,
        context,
        challenge_message,
    );
    defer proof_message.deinit(allocator);

    var store = libself.TrustStore.init(allocator);
    defer store.deinit();
    var peer = try libself.libfast.session.verifyProofMessage(
        allocator,
        .tofu,
        &store,
        context,
        challenge_message,
        proof_message,
    );
    defer peer.deinit();

    std.debug.print("authenticated did: {s}\n", .{peer.did});
    std.debug.print("trust: {any}\n", .{peer.trust});
    std.debug.print("node id: {s}\n", .{peer.node_id.toHex()});
}
