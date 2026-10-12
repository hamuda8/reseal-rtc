//! Opus RTP payload format (RFC 7587): one Opus packet per RTP payload, 48 kHz RTP clock
//! regardless of the coded bandwidth. `packetSamples` reads the TOC (RFC 6716 3.1) so the
//! sender can advance the RTP timestamp by the real packet duration.

const std = @import("std");

pub const clock_rate = 48000;
pub const default_fmtp = "minptime=10;useinbandfec=1";

/// Samples at 48 kHz in an Opus packet, from its TOC byte and frame count code.
pub fn packetSamples(packet: []const u8) !u32 {
    if (packet.len == 0) return error.EmptyPacket;
    const toc = packet[0];
    const config = toc >> 3;
    // Frame sizes in 48 kHz samples for each configuration group.
    const frame: u32 = if (config < 12)
        ([_]u32{ 480, 960, 1920, 2880 })[config & 3] // SILK: 10/20/40/60 ms
    else if (config < 16)
        ([_]u32{ 480, 960 })[config & 1] // Hybrid: 10/20 ms
    else
        ([_]u32{ 120, 240, 480, 960 })[config & 3]; // CELT: 2.5/5/10/20 ms
    const frames: u32 = switch (toc & 3) {
        0 => 1,
        1, 2 => 2,
        3 => if (packet.len < 2) return error.Truncated else packet[1] & 0x3F,
        else => unreachable,
    };
    if (frames == 0 or frame * frames > 5760) return error.BadPacket; // max 120 ms
    return frame * frames;
}

test "TOC durations" {
    try std.testing.expectEqual(@as(u32, 960), try packetSamples(&.{0xF8})); // CELT FB 20 ms
    try std.testing.expectEqual(@as(u32, 960), try packetSamples(&.{0x08})); // SILK NB 20 ms
    try std.testing.expectEqual(@as(u32, 1920), try packetSamples(&.{0xF9})); // two 20 ms frames
    try std.testing.expectEqual(@as(u32, 2880), try packetSamples(&.{ 0xFB, 0x03 })); // three
}
