//! reseal-rtc: a zero-dependency WebRTC wire-protocol engine (ICE, DTLS-SRTP, RTP, SDP).

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // No target or optimize: the module takes the importing app's (Android, iOS, wasm...).
    const rtc = b.addModule("reseal_rtc", .{ .root_source_file = b.path("src/root.zig") });

    const test_step = b.step("test", "Run reseal-rtc tests");
    const tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    }) });
    test_step.dependOn(&b.addRunArtifact(tests).step);

    // Interop harness against a real browser: zig build interop, then node tools/interop/run.mjs.
    const interop = b.addExecutable(.{
        .name = "rtc-interop",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "reseal_rtc", .module = rtc }},
        }),
    });
    const interop_step = b.step("interop", "Build the browser interop harness");
    interop_step.dependOn(&b.addInstallArtifact(interop, .{}).step);
}
