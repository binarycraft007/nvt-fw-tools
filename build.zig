const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const cflags = [_][]const u8{
        "-D_GNU_SOURCE", "-D_FILE_OFFSET_BITS=64",
    };

    const tools = [_][]const u8{
        "nvt_cksm",
        "nvt_sign",
        "nvtpack",
    };

    inline for (tools) |tool_name| {
        const tool = b.addExecutable(.{
            .name = tool_name,
            .root_module = b.createModule(.{
                .target = target,
                .optimize = optimize,
                .link_libc = true,
            }),
        });
        tool.root_module.linkSystemLibrary("crypto", .{});
        tool.root_module.addCSourceFile(.{
            .file = b.path(b.pathJoin(&.{ "src", tool_name ++ ".c" })),
            .flags = &cflags,
        });
        tool.root_module.addIncludePath(b.path("include"));
        b.installArtifact(tool);
    }
}
