const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const libself_module = b.createModule(.{
        .root_source_file = b.path("lib/libself.zig"),
        .target = target,
        .optimize = optimize,
    });

    _ = b.addModule("libself", .{
        .root_source_file = b.path("lib/libself.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addLibrary(.{
        .name = "self",
        .root_module = libself_module,
        .linkage = .static,
    });
    b.installArtifact(lib);

    const lib_unit_tests = b.addTest(.{
        .root_module = libself_module,
    });
    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);

    const bin_module = b.createModule(.{
        .root_source_file = b.path("bin/libself.zig"),
        .target = target,
        .optimize = optimize,
    });
    bin_module.addImport("libself", libself_module);

    const bin = b.addExecutable(.{
        .name = "libself",
        .root_module = bin_module,
    });
    b.installArtifact(bin);

    const run_bin = b.addRunArtifact(bin);
    const run_step = b.step("run", "Run the libself binary");
    run_step.dependOn(&run_bin.step);

    const example_module = b.createModule(.{
        .root_source_file = b.path("examples/hello_world.zig"),
        .target = target,
        .optimize = optimize,
    });

    const example = b.addExecutable(.{
        .name = "hello_world",
        .root_module = example_module,
    });
    b.installArtifact(example);

    const run_example = b.addRunArtifact(example);
    const run_example_step = b.step("run-example", "Run the hello world example");
    run_example_step.dependOn(&run_example.step);
}
