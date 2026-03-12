pub fn hello() []const u8 {
    return "hello from libself";
}

test {
    try @import("std").testing.expectEqualStrings("hello from libself", hello());
}
