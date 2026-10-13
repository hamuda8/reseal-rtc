//! Send-side bitrate for our video, from what the receiver reports: REMB (its estimate of the
//! path), and loss and round-trip time from RTCP receiver reports. Loss-based like libwebrtc's
//! sender side: above 10 % loss the target drops in proportion, below 2 % it grows by 8 % a
//! second, in between it holds; a rising RTT stops growth. The result never exceeds a recent
//! REMB and stays within [min, max].

const std = @import("std");
const BitrateController = @This();

pub const Config = struct {
    start: u32 = 600_000,
    min: u32 = 80_000,
    max: u32 = 1_500_000,
};

config: Config,
target: f64,
remb: ?u32 = null,
remb_at: u64 = 0,
last_increase: u64 = 0,
loss: f32 = 0,
rtt_ms: ?u32 = null,
min_rtt_ms: u32 = std.math.maxInt(u32),

pub fn init(config: Config) BitrateController {
    return .{ .config = config, .target = @floatFromInt(config.start) };
}

/// A REMB from the receiver (bits per second).
pub fn onRemb(b: *BitrateController, now: u64, bps: u64) void {
    b.remb = @intCast(@min(bps, std.math.maxInt(u32)));
    b.remb_at = now;
}

/// A receiver report block about our video: `fraction_lost` as sent (0..255) and the RTT, if
/// it could be computed.
pub fn onReport(b: *BitrateController, now: u64, fraction_lost: u8, rtt_ms: ?u32) void {
    const loss = @as(f32, @floatFromInt(fraction_lost)) / 256.0;
    b.loss = loss;
    if (rtt_ms) |r| {
        b.rtt_ms = r;
        b.min_rtt_ms = @min(b.min_rtt_ms, r);
    }
    // Queues building up show as RTT well above the best seen: do not push harder then.
    const congested = if (b.rtt_ms) |r| r > b.min_rtt_ms * 2 + 100 else false;
    if (loss > 0.10) {
        b.target *= 1.0 - 0.5 * loss;
    } else if (loss < 0.02 and !congested and now >= b.last_increase + 1000) {
        b.target *= 1.08;
        b.last_increase = now;
    } else if (congested) {
        b.target *= 0.95;
    }
    b.clamp(now);
}

fn clamp(b: *BitrateController, now: u64) void {
    const max: f64 = @floatFromInt(b.config.max);
    const min: f64 = @floatFromInt(b.config.min);
    // A recent REMB bounds the target (the receiver knows its downlink); a stale one does not.
    const cap = if (b.remb) |r| (if (now < b.remb_at + 5000) @max(@as(f64, @floatFromInt(r)), min) else max) else max;
    b.target = std.math.clamp(b.target, min, @min(max, cap * 1.0));
}

/// The bitrate to encode at now.
pub fn current(b: *BitrateController, now: u64) u32 {
    b.clamp(now);
    return @intFromFloat(b.target);
}

const testing = std.testing;

test "loss lowers, a clean link raises, REMB caps" {
    var b = init(.{ .start = 600_000 });
    b.onReport(0, 64, 50); // 25 % loss
    try testing.expect(b.current(0) < 600_000 * 0.9);
    const low = b.current(0);
    var t: u64 = 0;
    for (0..20) |_| {
        t += 1000;
        b.onReport(t, 0, 50);
    }
    try testing.expect(b.current(t) > low * 2);
    b.onRemb(t, 300_000);
    try testing.expectEqual(@as(u32, 300_000), b.current(t));
    // A REMB that stopped coming no longer caps.
    for (0..10) |_| {
        t += 1000;
        b.onReport(t, 0, 50);
    }
    try testing.expect(b.current(t) > 300_000);
    // Growing RTT stops growth.
    const before = b.current(t);
    t += 1000;
    b.onReport(t, 0, 600);
    try testing.expect(b.current(t) <= before);
}
