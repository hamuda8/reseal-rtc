//! Reorders received RTP packets and releases whole frames in order.
//!
//! A video frame is the run of packets sharing a timestamp, ending with the marker bit; an
//! audio frame is one packet. A frame is released as soon as it is complete and everything
//! before it was released. If a gap is not filled within `max_delay_ms` (NACK retransmissions
//! get that long), the buffer skips to the next frame start and flags the discontinuity so
//! video can ask for a keyframe. `missing` lists sequence numbers worth NACKing.

const std = @import("std");
const rtp = @import("rtp.zig");
const JitterBuffer = @This();

pub const Kind = enum { audio, video };

const capacity = 1024; // packets; a 30 KB keyframe at 1200 bytes is ~25

const Slot = struct {
    seq: u64,
    timestamp: u32,
    marker: bool,
    arrived: u64,
    data: []u8,
};

pub const Frame = struct {
    timestamp: u32,
    /// Payloads in sequence order; valid until the next `pop` or `push`.
    payloads: []const []const u8,
    /// Packets were skipped before this frame.
    discontinuity: bool,
};

gpa: std.mem.Allocator,
kind: Kind,
max_delay_ms: u64,
slots: [capacity]?Slot = @splat(null),
next: ?u64 = null,
highest: u64 = 0,
skipped_pending: bool = false,
/// Until the first frame is released, an earlier packet may still become the head.
released_any: bool = false,
out: std.ArrayList([]const u8) = .empty,
released: std.ArrayList([]u8) = .empty,
stats: struct { received: u64 = 0, duplicates: u64 = 0, late: u64 = 0, skipped: u64 = 0 } = .{},

pub fn init(gpa: std.mem.Allocator, kind: Kind, max_delay_ms: u64) JitterBuffer {
    return .{ .gpa = gpa, .kind = kind, .max_delay_ms = max_delay_ms };
}

pub fn deinit(j: *JitterBuffer) void {
    j.freeReleased();
    for (&j.slots) |*s| if (s.*) |slot| {
        j.gpa.free(slot.data);
        s.* = null;
    };
    j.out.deinit(j.gpa);
    j.released.deinit(j.gpa);
}

fn freeReleased(j: *JitterBuffer) void {
    for (j.released.items) |d| j.gpa.free(d);
    j.released.clearRetainingCapacity();
    j.out.clearRetainingCapacity();
}

/// Stores a packet's payload. Returns false for duplicates and packets that are too late.
pub fn push(j: *JitterBuffer, seq16: u16, timestamp: u32, marker: bool, payload: []const u8, now: u64) !bool {
    j.freeReleased();
    const seq = if (j.next == null) @as(u64, seq16) + 0x10000 else rtp.extendSeq(j.highest, seq16);
    if (j.next == null) {
        j.next = seq;
        j.highest = seq;
    }
    if (seq < j.next.? and !j.released_any and j.next.? - seq < 128) j.next = seq;
    if (seq < j.next.?) {
        j.stats.late += 1;
        return false;
    }
    if (seq >= j.next.? + capacity) {
        // Far ahead (a long outage): restart from here.
        j.dropAll();
        j.next = seq;
        j.skipped_pending = true;
    }
    const idx = seq % capacity;
    if (j.slots[idx]) |s| if (s.seq == seq) {
        j.stats.duplicates += 1;
        return false;
    };
    j.stats.received += 1;
    j.slots[idx] = .{ .seq = seq, .timestamp = timestamp, .marker = marker, .arrived = now, .data = try j.gpa.dupe(u8, payload) };
    j.highest = @max(j.highest, seq);
    return true;
}

fn dropAll(j: *JitterBuffer) void {
    for (&j.slots) |*s| if (s.*) |slot| {
        j.gpa.free(slot.data);
        s.* = null;
    };
}

fn get(j: *const JitterBuffer, seq: u64) ?Slot {
    const s = j.slots[seq % capacity] orelse return null;
    return if (s.seq == seq) s else null;
}

/// Releases the next complete frame, skipping a gap that has waited longer than allowed.
pub fn pop(j: *JitterBuffer, now: u64) ?Frame {
    j.freeReleased();
    const start = j.next orelse return null;
    if (j.completeFrom(start)) |end| return j.release(start, end);

    // Head missing or incomplete: give up on it once something later is old enough.
    var oldest: ?u64 = null;
    var s = start;
    while (s <= j.highest) : (s += 1) if (j.get(s)) |slot| {
        oldest = if (oldest) |o| @min(o, slot.arrived) else slot.arrived;
    };
    const o = oldest orelse return null;
    if (now < o + j.max_delay_ms) return null;

    // Skip to the first packet that starts a frame: after a marker (video) or any (audio).
    s = start;
    var resume_at: ?u64 = null;
    while (s <= j.highest) : (s += 1) {
        const slot = j.get(s) orelse continue;
        if (j.kind == .audio and s > start) {
            resume_at = s;
            break;
        }
        if (slot.marker and s + 1 <= j.highest) {
            resume_at = s + 1;
            break;
        }
    }
    const to = resume_at orelse return null;
    var k = start;
    while (k < to) : (k += 1) if (j.get(k)) |slot| {
        j.gpa.free(slot.data);
        j.slots[k % capacity] = null;
    };
    j.stats.skipped += to - start;
    j.next = to;
    j.released_any = true;
    j.skipped_pending = true;
    if (j.completeFrom(to)) |end| return j.release(to, end);
    return null;
}

/// The last sequence of the frame beginning at `start`, if all of it is present.
fn completeFrom(j: *const JitterBuffer, start: u64) ?u64 {
    const first = j.get(start) orelse return null;
    if (j.kind == .audio) return start;
    var s = start;
    while (j.get(s)) |slot| : (s += 1) {
        if (slot.timestamp != first.timestamp) return s - 1; // marker lost, next frame began
        if (slot.marker) return s;
    }
    return null;
}

fn release(j: *JitterBuffer, start: u64, end: u64) Frame {
    var s = start;
    const ts = j.get(start).?.timestamp;
    while (s <= end) : (s += 1) {
        const slot = j.get(s).?;
        j.out.append(j.gpa, slot.data) catch {};
        j.released.append(j.gpa, slot.data) catch {};
        j.slots[s % capacity] = null;
    }
    j.next = end + 1;
    j.released_any = true;
    const disc = j.skipped_pending;
    j.skipped_pending = false;
    return .{ .timestamp = ts, .payloads = j.out.items, .discontinuity = disc };
}

/// Sequence numbers (16-bit) missing between the next frame and the newest packet.
pub fn missing(j: *const JitterBuffer, out: []u16) []u16 {
    const start = j.next orelse return out[0..0];
    var n: usize = 0;
    var s = start;
    while (s < j.highest and n < out.len) : (s += 1) {
        if (j.get(s) == null) {
            out[n] = @truncate(s);
            n += 1;
        }
    }
    return out[0..n];
}

const testing = std.testing;

test "reorders video packets into frames" {
    var j = init(testing.allocator, .video, 100);
    defer j.deinit();
    _ = try j.push(11, 90, false, "b", 0);
    try testing.expect(j.pop(0) == null);
    _ = try j.push(10, 90, false, "a", 0);
    try testing.expect(j.pop(0) == null);
    _ = try j.push(12, 90, true, "c", 0);
    const f = j.pop(0).?;
    try testing.expectEqual(@as(usize, 3), f.payloads.len);
    try testing.expectEqualStrings("a", f.payloads[0]);
    try testing.expectEqualStrings("c", f.payloads[2]);
    try testing.expect(!f.discontinuity);
    // duplicate / late
    try testing.expect(!try j.push(12, 90, true, "c", 0));
}

test "a lost packet is reported missing, then skipped with a discontinuity" {
    var j = init(testing.allocator, .video, 100);
    defer j.deinit();
    _ = try j.push(1, 10, true, "f1", 0);
    try testing.expect(j.pop(0) != null);
    _ = try j.push(2, 20, false, "f2a", 0); // 3 is lost
    _ = try j.push(4, 20, true, "f2c", 0);
    _ = try j.push(5, 30, true, "f3", 0);
    var buf: [8]u16 = undefined;
    try testing.expectEqualSlices(u16, &.{3}, j.missing(&buf));
    try testing.expect(j.pop(50) == null); // still waiting for the retransmission
    const f = j.pop(200).?;
    try testing.expectEqual(@as(u32, 30), f.timestamp);
    try testing.expect(f.discontinuity);
}

test "audio across sequence wrap" {
    var j = init(testing.allocator, .audio, 60);
    defer j.deinit();
    _ = try j.push(65535, 0, true, "x", 0);
    _ = try j.push(0, 960, true, "y", 0);
    try testing.expectEqualStrings("x", j.pop(0).?.payloads[0]);
    try testing.expectEqualStrings("y", j.pop(0).?.payloads[0]);
}
