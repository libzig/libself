const std = @import("std");

pub const Error = error{InvalidCharacter};

const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub fn encodeAlloc(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    if (bytes.len == 0) {
        return allocator.alloc(u8, 0);
    }

    const leading_zero_count = countLeadingZeros(bytes);
    const size = ((bytes.len - leading_zero_count) * 138 / 100) + 1;
    const digits = try allocator.alloc(u8, size);
    defer allocator.free(digits);
    @memset(digits, 0);

    var length: usize = 0;
    for (bytes[leading_zero_count..]) |byte| {
        var carry: usize = byte;
        var used: usize = 0;
        var index = size;

        while ((carry != 0 or used < length) and index > 0) : (used += 1) {
            index -= 1;
            carry += @as(usize, digits[index]) * 256;
            digits[index] = @intCast(carry % 58);
            carry /= 58;
        }

        length = used;
    }

    var first_digit = size - length;
    while (first_digit < size and digits[first_digit] == 0) {
        first_digit += 1;
    }

    const encoded_len = leading_zero_count + (size - first_digit);
    const out = try allocator.alloc(u8, encoded_len);
    @memset(out[0..leading_zero_count], '1');

    for (digits[first_digit..], 0..) |digit, i| {
        out[leading_zero_count + i] = alphabet[digit];
    }

    return out;
}

pub fn decodeAlloc(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    if (text.len == 0) {
        return allocator.alloc(u8, 0);
    }

    const leading_zero_count = countLeadingOnes(text);
    const size = ((text.len - leading_zero_count) * 733 / 1000) + 1;
    const bytes = try allocator.alloc(u8, size);
    defer allocator.free(bytes);
    @memset(bytes, 0);

    var length: usize = 0;
    for (text[leading_zero_count..]) |ch| {
        const value = try alphabetIndex(ch);
        var carry: usize = value;
        var used: usize = 0;
        var index = size;

        while ((carry != 0 or used < length) and index > 0) : (used += 1) {
            index -= 1;
            carry += @as(usize, bytes[index]) * 58;
            bytes[index] = @intCast(carry % 256);
            carry /= 256;
        }

        length = used;
    }

    var first_byte = size - length;
    while (first_byte < size and bytes[first_byte] == 0) {
        first_byte += 1;
    }

    const decoded_len = leading_zero_count + (size - first_byte);
    const out = try allocator.alloc(u8, decoded_len);
    @memset(out[0..leading_zero_count], 0);
    @memcpy(out[leading_zero_count..], bytes[first_byte..]);

    return out;
}

fn countLeadingZeros(bytes: []const u8) usize {
    var count: usize = 0;
    while (count < bytes.len and bytes[count] == 0) {
        count += 1;
    }
    return count;
}

fn countLeadingOnes(text: []const u8) usize {
    var count: usize = 0;
    while (count < text.len and text[count] == '1') {
        count += 1;
    }
    return count;
}

fn alphabetIndex(ch: u8) Error!u8 {
    const maybe_index = std.mem.indexOfScalar(u8, alphabet, ch);
    return if (maybe_index) |index| @intCast(index) else error.InvalidCharacter;
}

test "base58btc roundtrip preserves leading zeros" {
    const allocator = std.testing.allocator;
    const input = [_]u8{ 0, 0, 1, 2, 3, 4, 5, 255 };

    const encoded = try encodeAlloc(allocator, &input);
    defer allocator.free(encoded);

    const decoded = try decodeAlloc(allocator, encoded);
    defer allocator.free(decoded);

    try std.testing.expectEqualStrings("11W7LcU3Q", encoded);
    try std.testing.expectEqualSlices(u8, &input, decoded);
}

test "base58btc rejects invalid characters" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.InvalidCharacter, decodeAlloc(allocator, "0OIl"));
}
