const std = @import("std");
const libsafe = @import("libsafe");

const Ed25519 = std.crypto.sign.Ed25519;

pub const public_key_len = 32;
pub const private_key_len = 64;
pub const PublicKey = [32]u8;
pub const PrivateKey = [64]u8;
pub const Signature = [64]u8;
pub const Seed = [32]u8;

pub const KeyPair = struct {
    public_key: PublicKey,
    private_key: PrivateKey,

    pub fn generate(random: std.Random) KeyPair {
        const generated = libsafe.ssh_signature.KeyPair.generate(random);
        return .{
            .public_key = generated.public_key,
            .private_key = generated.private_key,
        };
    }

    pub fn fromSeed(seed: Seed) !KeyPair {
        const generated = try Ed25519.KeyPair.generateDeterministic(seed);
        return .{
            .public_key = generated.public_key.toBytes(),
            .private_key = generated.secret_key.toBytes(),
        };
    }

    pub fn sign(self: KeyPair, message: []const u8) !Signature {
        return signWithPrivateKey(message, self.private_key);
    }

    pub fn verify(self: KeyPair, message: []const u8, signature: Signature) bool {
        return verifyWithPublicKey(message, signature, self.public_key);
    }
};

pub fn signWithPrivateKey(message: []const u8, private_key: PrivateKey) !Signature {
    return libsafe.ssh_signature.sign(message, &private_key);
}

pub fn verifyWithPublicKey(message: []const u8, signature: Signature, public_key: PublicKey) bool {
    return libsafe.ssh_signature.verify_ed25519(message, &signature, &public_key);
}

test "identity keypair generation signs and verifies" {
    var prng = std.Random.DefaultPrng.init(7);
    const key_pair = KeyPair.generate(prng.random());
    const signature = try key_pair.sign("libself");

    try std.testing.expect(key_pair.verify("libself", signature));
    try std.testing.expect(!key_pair.verify("wrong", signature));
}

test "identity keypair from seed is deterministic" {
    const seed = [_]u8{0x11} ** 32;
    const a = try KeyPair.fromSeed(seed);
    const b = try KeyPair.fromSeed(seed);
    const signature = try a.sign("deterministic");

    try std.testing.expectEqualSlices(u8, &a.public_key, &b.public_key);
    try std.testing.expectEqualSlices(u8, &a.private_key, &b.private_key);
    try std.testing.expect(verifyWithPublicKey("deterministic", signature, b.public_key));
}
