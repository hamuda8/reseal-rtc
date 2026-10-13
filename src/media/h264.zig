//! H.264 RTP payload format (RFC 6184), packetization-mode 1: single NAL unit packets,
//! STAP-A aggregation of small NALs (SPS/PPS before an IDR) and FU-A fragmentation.
//! Frames go in and come out in Annex-B form (start codes), which is what Android MediaCodec
//! and (after conversion from AVCC) iOS VideoToolbox use.

const std = @import("std");

pub const nal_stap_a = 24;
pub const nal_fu_a = 28;

pub const NalType = enum(u5) {
    slice = 1,
    idr = 5,
    sei = 6,
    sps = 7,
    pps = 8,
    aud = 9,
    _,
};

/// Iterates NAL units in an Annex-B byte stream (3- or 4-byte start codes).
pub const AnnexBIterator = struct {
    data: []const u8,
    pos: usize = 0,

    pub fn next(it: *AnnexBIterator) ?[]const u8 {
        const start = findStart(it.data, it.pos) orelse return null;
        const body = start.end;
        const following = findStart(it.data, body);
        var end = if (following) |f| f.begin else it.data.len;
        // Trailing zero bytes belong to the next start code (4-byte form).
        while (end > body and it.data[end - 1] == 0 and following != null) end -= 1;
        it.pos = if (following) |f| f.begin else it.data.len;
        if (end <= body) return it.next();
        return it.data[body..end];
    }

    fn findStart(d: []const u8, from: usize) ?struct { begin: usize, end: usize } {
        var i = from;
        while (i + 3 <= d.len) : (i += 1) {
            if (d[i] == 0 and d[i + 1] == 0 and d[i + 2] == 1) return .{ .begin = i, .end = i + 3 };
        }
        return null;
    }
};

pub fn nalType(nal: []const u8) NalType {
    return @fromBackingInt(@intCast(@as(u5, @truncate(nal[0]))));
}

/// True if the access unit contains an IDR slice.
pub fn isKeyframe(annexb: []const u8) bool {
    var it: AnnexBIterator = .{ .data = annexb };
    while (it.next()) |nal| if (nalType(nal) == .idr) return true;
    return false;
}

/// Splits one access unit into RTP payloads of at most `max` bytes. `emit` is called for
/// each payload with `marker` set on the last one of the frame.
pub fn packetize(annexb: []const u8, max: usize, ctx: anytype, comptime emit: fn (@TypeOf(ctx), payload: []const u8, marker: bool) void) void {
    std.debug.assert(max >= 64);
    var it: AnnexBIterator = .{ .data = annexb };
    var nals: [64][]const u8 = undefined;
    var count: usize = 0;
    while (it.next()) |nal| {
        // Access unit delimiters carry nothing for the receiver.
        if (nalType(nal) == .aud) continue;
        if (count == nals.len) break;
        nals[count] = nal;
        count += 1;
    }
    var buf: [1500]u8 = undefined;
    var i: usize = 0;
    while (i < count) {
        const nal = nals[i];
        if (nal.len > max) {
            // FU-A: indicator keeps F and NRI, header carries S/E and the original type.
            const indicator = (nal[0] & 0xE0) | nal_fu_a;
            var off: usize = 1;
            while (off < nal.len) {
                const n = @min(max - 2, nal.len - off);
                const last = off + n == nal.len;
                buf[0] = indicator;
                buf[1] = (nal[0] & 0x1F) | (if (off == 1) @as(u8, 0x80) else 0) | (if (last) @as(u8, 0x40) else 0);
                @memcpy(buf[2..][0..n], nal[off..][0..n]);
                emit(ctx, buf[0 .. 2 + n], last and i + 1 == count);
                off += n;
            }
            i += 1;
            continue;
        }
        // Aggregate following small NALs while they fit in one STAP-A.
        var j = i;
        var size: usize = 1;
        var nri: u8 = 0;
        while (j < count and nals[j].len <= max and size + 2 + nals[j].len <= max) : (j += 1) {
            size += 2 + nals[j].len;
            nri = @max(nri, nals[j][0] & 0x60);
        }
        if (j - i <= 1) {
            emit(ctx, nal, i + 1 == count);
            i += 1;
            continue;
        }
        buf[0] = nri | nal_stap_a;
        var at: usize = 1;
        for (nals[i..j]) |n| {
            std.mem.writeInt(u16, buf[at..][0..2], @intCast(n.len), .big);
            @memcpy(buf[at + 2 ..][0..n.len], n);
            at += 2 + n.len;
        }
        emit(ctx, buf[0..at], j == count);
        i = j;
    }
}

/// Reassembles payloads of one frame (in sequence order) into Annex-B.
pub const Depacketizer = struct {
    out: std.ArrayList(u8) = .empty,
    in_fu: bool = false,
    corrupt: bool = false,

    pub fn deinit(d: *Depacketizer, gpa: std.mem.Allocator) void {
        d.out.deinit(gpa);
    }

    pub fn reset(d: *Depacketizer) void {
        d.out.clearRetainingCapacity();
        d.in_fu = false;
        d.corrupt = false;
    }

    const start_code = [_]u8{ 0, 0, 0, 1 };

    pub fn push(d: *Depacketizer, gpa: std.mem.Allocator, payload: []const u8) !void {
        if (payload.len == 0) return;
        const t = payload[0] & 0x1F;
        switch (t) {
            1...23 => {
                d.in_fu = false;
                try d.out.appendSlice(gpa, &start_code);
                try d.out.appendSlice(gpa, payload);
            },
            nal_stap_a => {
                var i: usize = 1;
                while (i + 2 <= payload.len) {
                    const n = std.mem.readInt(u16, payload[i..][0..2], .big);
                    if (i + 2 + n > payload.len) {
                        d.corrupt = true;
                        return;
                    }
                    try d.out.appendSlice(gpa, &start_code);
                    try d.out.appendSlice(gpa, payload[i + 2 ..][0..n]);
                    i += 2 + n;
                }
            },
            nal_fu_a => {
                if (payload.len < 2) return;
                const s = payload[1] & 0x80 != 0;
                if (s) {
                    try d.out.appendSlice(gpa, &start_code);
                    try d.out.append(gpa, (payload[0] & 0xE0) | (payload[1] & 0x1F));
                    d.in_fu = true;
                } else if (!d.in_fu) {
                    d.corrupt = true; // lost the start of this NAL
                    return;
                }
                try d.out.appendSlice(gpa, payload[2..]);
                if (payload[1] & 0x40 != 0) d.in_fu = false;
            },
            else => {}, // STAP-B, MTAP, FU-B: not used in packetization-mode 1 by browsers
        }
    }

    pub fn frame(d: *const Depacketizer) []const u8 {
        return d.out.items;
    }
};

const testing = std.testing;

const Collector = struct {
    gpa: std.mem.Allocator,
    payloads: std.ArrayList([]u8) = .empty,
    markers: std.ArrayList(bool) = .empty,

    fn emit(c: *Collector, p: []const u8, marker: bool) void {
        c.payloads.append(c.gpa, c.gpa.dupe(u8, p) catch unreachable) catch unreachable;
        c.markers.append(c.gpa, marker) catch unreachable;
    }

    fn deinit(c: *Collector) void {
        for (c.payloads.items) |p| c.gpa.free(p);
        c.payloads.deinit(c.gpa);
        c.markers.deinit(c.gpa);
    }
};

test "STAP-A for SPS/PPS, FU-A for a large IDR, single NAL; round trip" {
    const gpa = testing.allocator;
    var frame: std.ArrayList(u8) = .empty;
    defer frame.deinit(gpa);
    try frame.appendSlice(gpa, &.{ 0, 0, 0, 1, 0x67, 0x42, 0xe0, 0x1f, 0xaa }); // SPS
    try frame.appendSlice(gpa, &.{ 0, 0, 0, 1, 0x68, 0xce, 0x3c, 0x80 }); // PPS
    try frame.appendSlice(gpa, &.{ 0, 0, 1, 0x65 }); // IDR, 3000 bytes of body
    for (0..3000) |i| try frame.append(gpa, @truncate(i * 7 + 1));
    try frame.appendSlice(gpa, &.{ 0, 0, 0, 1, 0x06, 0x05, 0x01, 0x02 }); // SEI after

    var c: Collector = .{ .gpa = gpa };
    defer c.deinit();
    packetize(frame.items, 1200, &c, Collector.emit);
    // STAP-A(SPS,PPS), 3 FU-A fragments of the IDR, then the SEI alone.
    try testing.expectEqual(@as(usize, 5), c.payloads.items.len);
    try testing.expectEqual(@as(u8, nal_stap_a), c.payloads.items[0][0] & 0x1F);
    try testing.expectEqual(@as(u8, 0x60), c.payloads.items[0][0] & 0x60); // max NRI
    try testing.expectEqual(@as(u8, nal_fu_a), c.payloads.items[1][0] & 0x1F);
    try testing.expectEqual(@as(u8, 0x85), c.payloads.items[1][1]); // S + IDR
    try testing.expectEqual(@as(u8, 0x45), c.payloads.items[3][1]); // E + IDR
    try testing.expectEqualSlices(bool, &.{ false, false, false, false, true }, c.markers.items);
    for (c.payloads.items) |p| try testing.expect(p.len <= 1200);

    var d: Depacketizer = .{};
    defer d.deinit(gpa);
    for (c.payloads.items) |p| try d.push(gpa, p);
    try testing.expect(!d.corrupt);
    // Output uses 4-byte start codes everywhere; compare NAL by NAL.
    var a: AnnexBIterator = .{ .data = frame.items };
    var b: AnnexBIterator = .{ .data = d.frame() };
    while (a.next()) |na| try testing.expectEqualSlices(u8, na, b.next().?);
    try testing.expect(b.next() == null);
    try testing.expect(isKeyframe(d.frame()));
}

test "lost FU-A start marks the frame corrupt" {
    var d: Depacketizer = .{};
    defer d.deinit(testing.allocator);
    try d.push(testing.allocator, &.{ 0x7C, 0x05, 1, 2, 3 }); // middle fragment
    try testing.expect(d.corrupt);
}
