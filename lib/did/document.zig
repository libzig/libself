const std = @import("std");

pub const VerificationMethod = struct {
    id: []u8,
    controller: []u8,
    type_name: []const u8,
    public_key_multibase: []u8,

    pub fn deinit(self: *VerificationMethod, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.controller);
        allocator.free(self.public_key_multibase);
    }
};

pub const Document = struct {
    id: []u8,
    verification_method: VerificationMethod,

    pub fn deinit(self: *Document, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        self.verification_method.deinit(allocator);
    }
};
