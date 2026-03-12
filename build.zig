const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const libsafe_dep = b.dependency("libsafe", .{
        .target = target,
        .optimize = optimize,
    });
    const libsafe_module = libsafe_dep.module("libsafe");

    const libself_module = b.createModule(.{
        .root_source_file = b.path("lib/libself.zig"),
        .target = target,
        .optimize = optimize,
    });
    libself_module.addImport("libsafe", libsafe_module);

    const exported = b.addModule("libself", .{
        .root_source_file = b.path("lib/libself.zig"),
        .target = target,
        .optimize = optimize,
    });
    exported.addImport("libsafe", libsafe_module);

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
    bin_module.addImport("libsafe", libsafe_module);

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
    example_module.addImport("libself", libself_module);
    example_module.addImport("libsafe", libsafe_module);

    const example = b.addExecutable(.{
        .name = "hello_world",
        .root_module = example_module,
    });
    b.installArtifact(example);

    const run_example = b.addRunArtifact(example);
    const run_example_step = b.step("run-example", "Run the hello world example");
    run_example_step.dependOn(&run_example.step);

    const did_key_example_module = b.createModule(.{
        .root_source_file = b.path("examples/did_key_roundtrip.zig"),
        .target = target,
        .optimize = optimize,
    });
    did_key_example_module.addImport("libself", libself_module);

    const did_key_example = b.addExecutable(.{
        .name = "did_key_roundtrip",
        .root_module = did_key_example_module,
    });
    b.installArtifact(did_key_example);

    const run_did_key_example = b.addRunArtifact(did_key_example);
    const run_did_key_example_step = b.step("run-did-key-roundtrip", "Run the did:key roundtrip example");
    run_did_key_example_step.dependOn(&run_did_key_example.step);

    const auth_example_module = b.createModule(.{
        .root_source_file = b.path("examples/auth_challenge.zig"),
        .target = target,
        .optimize = optimize,
    });
    auth_example_module.addImport("libself", libself_module);

    const auth_example = b.addExecutable(.{
        .name = "auth_challenge",
        .root_module = auth_example_module,
    });
    b.installArtifact(auth_example);

    const run_auth_example = b.addRunArtifact(auth_example);
    const run_auth_example_step = b.step("run-auth-challenge", "Run the auth challenge example");
    run_auth_example_step.dependOn(&run_auth_example.step);

    const trust_example_module = b.createModule(.{
        .root_source_file = b.path("examples/trust_tofu.zig"),
        .target = target,
        .optimize = optimize,
    });
    trust_example_module.addImport("libself", libself_module);

    const trust_example = b.addExecutable(.{
        .name = "trust_tofu",
        .root_module = trust_example_module,
    });
    b.installArtifact(trust_example);

    const run_trust_example = b.addRunArtifact(trust_example);
    const run_trust_example_step = b.step("run-trust-tofu", "Run the TOFU trust example");
    run_trust_example_step.dependOn(&run_trust_example.step);

    const profile_example_module = b.createModule(.{
        .root_source_file = b.path("examples/profile_roundtrip.zig"),
        .target = target,
        .optimize = optimize,
    });
    profile_example_module.addImport("libself", libself_module);

    const profile_example = b.addExecutable(.{
        .name = "profile_roundtrip",
        .root_module = profile_example_module,
    });
    b.installArtifact(profile_example);

    const run_profile_example = b.addRunArtifact(profile_example);
    const run_profile_example_step = b.step("run-profile-roundtrip", "Run the profile roundtrip example");
    run_profile_example_step.dependOn(&run_profile_example.step);

    const libfast_example_module = b.createModule(.{
        .root_source_file = b.path("examples/libfast_identity_handshake.zig"),
        .target = target,
        .optimize = optimize,
    });
    libfast_example_module.addImport("libself", libself_module);

    const libfast_example = b.addExecutable(.{
        .name = "libfast_identity_handshake",
        .root_module = libfast_example_module,
    });
    b.installArtifact(libfast_example);

    const run_libfast_example = b.addRunArtifact(libfast_example);
    const run_libfast_example_step = b.step("run-libfast-identity-handshake", "Run the libfast identity handshake example");
    run_libfast_example_step.dependOn(&run_libfast_example.step);
}
