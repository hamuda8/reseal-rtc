//! RTCP (RFC 3550 6) and the feedback messages WebRTC needs (RFC 4585, RFC 5104):
//! SR, RR, SDES CNAME, BYE, generic NACK, PLI, FIR and REMB (draft-alvestrand-rmcat-remb).
//! Builders append to a buffer to form compound packets; `Iterator` walks received ones.

const std = @import("std");

pub const Type = enum(u8) {
    sr = 200,
    rr = 201,
    sdes = 202,
    bye = 203,
    app = 204,
    rtpfb = 205,
    psfb = 206,
    _,
};

pub const ReportBlock = struct {
    ssrc: u32,
    fraction_lost: u8 = 0,
    cumulative_lost: u24 = 0,
    highest_seq: u32 = 0,
    jitter: u32 = 0,
    last_sr: u32 = 0,
    delay_since_last_sr: u32 = 0,

    fn write(b: ReportBlock, out: *[24]u8) void {
        std.mem.writeInt(u32, out[0..4], b.ssrc, .big);
        out[4] = b.fraction_lost;
        std.mem.writeInt(u24, out[5..8], b.cumulative_lost, .big);
        std.mem.writeInt(u32, out[8..12], b.highest_seq, .big);
        std.mem.writeInt(u32, out[12..16], b.jitter, .big);
        std.mem.writeInt(u32, out[16..20], b.last_sr, .big);
        std.mem.writeInt(u32, out[20..24], b.delay_since_last_sr, .big);
    }

    fn read(in: *const [24]u8) ReportBlock {
        return .{
            .ssrc = std.mem.readInt(u32, in[0..4], .big),
            .fraction_lost = in[4],
            .cumulative_lost = std.mem.readInt(u24, in[5..8], .big),
            .highest_seq = std.mem.readInt(u32, in[8..12], .big),
            .jitter = std.mem.readInt(u32, in[12..16], .big),
            .last_sr = std.mem.readInt(u32, in[16..20], .big),
            .delay_since_last_sr = std.mem.readInt(u32, in[20..24], .big),
        };
    }
};

/// Appends RTCP packets into a fixed buffer.
pub const Builder = struct {
    buf: []u8,
    len: usize = 0,

    pub fn bytes(b: *const Builder) []u8 {
        return b.buf[0..b.len];
    }

    fn header(b: *Builder, count: u5, pt: Type, words_after: usize) ![]u8 {
        const total = 4 + 4 * words_after;
        if (b.len + total > b.buf.len) return error.NoSpaceLeft;
        const out = b.buf[b.len..][0..total];
        out[0] = 0x80 | @as(u8, count);
        out[1] = @intFromEnum(pt);
        std.mem.writeInt(u16, out[2..4], @intCast(words_after), .big);
        b.len += total;
        return out;
    }

    pub fn senderReport(b: *Builder, ssrc: u32, ntp: u64, rtp_ts: u32, packets: u32, octets: u32, blocks: []const ReportBlock) !void {
        const out = try b.header(@intCast(blocks.len), .sr, 6 + 6 * blocks.len);
        std.mem.writeInt(u32, out[4..8], ssrc, .big);
        std.mem.writeInt(u64, out[8..16], ntp, .big);
        std.mem.writeInt(u32, out[16..20], rtp_ts, .big);
        std.mem.writeInt(u32, out[20..24], packets, .big);
        std.mem.writeInt(u32, out[24..28], octets, .big);
        for (blocks, 0..) |blk, i| blk.write(out[28 + 24 * i ..][0..24]);
    }

    pub fn receiverReport(b: *Builder, ssrc: u32, blocks: []const ReportBlock) !void {
        const out = try b.header(@intCast(blocks.len), .rr, 1 + 6 * blocks.len);
        std.mem.writeInt(u32, out[4..8], ssrc, .big);
        for (blocks, 0..) |blk, i| blk.write(out[8 + 24 * i ..][0..24]);
    }

    /// SDES with one chunk carrying CNAME.
    pub fn sdesCname(b: *Builder, ssrc: u32, cname: []const u8) !void {
        const item_len = 2 + cname.len + 1; // CNAME item + END
        const words = (4 + item_len + 3) / 4;
        const out = try b.header(1, .sdes, words);
        @memset(out[4..], 0);
        std.mem.writeInt(u32, out[4..8], ssrc, .big);
        out[8] = 1; // CNAME
        out[9] = @intCast(cname.len);
        @memcpy(out[10..][0..cname.len], cname);
    }

    pub fn bye(b: *Builder, ssrc: u32) !void {
        const out = try b.header(1, .bye, 1);
        std.mem.writeInt(u32, out[4..8], ssrc, .big);
    }

    pub fn pli(b: *Builder, sender: u32, media: u32) !void {
        const out = try b.header(1, .psfb, 2);
        std.mem.writeInt(u32, out[4..8], sender, .big);
        std.mem.writeInt(u32, out[8..12], media, .big);
    }

    pub fn fir(b: *Builder, sender: u32, media: u32, seq_nr: u8) !void {
        const out = try b.header(4, .psfb, 4);
        std.mem.writeInt(u32, out[4..8], sender, .big);
        std.mem.writeInt(u32, out[8..12], 0, .big);
        std.mem.writeInt(u32, out[12..16], media, .big);
        out[16] = seq_nr;
        @memset(out[17..20], 0);
    }

    /// Generic NACK (RFC 4585 6.2.1) for `lost` sequence numbers (ascending).
    pub fn nack(b: *Builder, sender: u32, media: u32, lost: []const u16) !void {
        var pairs: [64][2]u16 = undefined;
        var n: usize = 0;
        var i: usize = 0;
        while (i < lost.len and n < pairs.len) {
            const pid = lost[i];
            var blp: u16 = 0;
            i += 1;
            while (i < lost.len) : (i += 1) {
                const d = lost[i] -% pid;
                if (d == 0) continue;
                if (d > 16) break;
                blp |= @as(u16, 1) << @intCast(d - 1);
            }
            pairs[n] = .{ pid, blp };
            n += 1;
        }
        const out = try b.header(1, .rtpfb, 2 + n);
        std.mem.writeInt(u32, out[4..8], sender, .big);
        std.mem.writeInt(u32, out[8..12], media, .big);
        for (pairs[0..n], 0..) |p, k| {
            std.mem.writeInt(u16, out[12 + 4 * k ..][0..2], p[0], .big);
            std.mem.writeInt(u16, out[14 + 4 * k ..][0..2], p[1], .big);
        }
    }

    /// REMB: receiver estimated maximum bitrate for `ssrcs`.
    pub fn remb(b: *Builder, sender: u32, bitrate: u64, ssrcs: []const u32) !void {
        const out = try b.header(15, .psfb, 4 + ssrcs.len);
        std.mem.writeInt(u32, out[4..8], sender, .big);
        std.mem.writeInt(u32, out[8..12], 0, .big);
        @memcpy(out[12..16], "REMB");
        var exp: u6 = 0;
        var mantissa = bitrate;
        while (mantissa > 0x3ffff) {
            mantissa >>= 1;
            exp += 1;
        }
        out[16] = @intCast(ssrcs.len);
        out[17] = (@as(u8, exp) << 2) | @as(u8, @intCast(mantissa >> 16));
        std.mem.writeInt(u16, out[18..20], @truncate(mantissa), .big);
        for (ssrcs, 0..) |s, i| std.mem.writeInt(u32, out[20 + 4 * i ..][0..4], s, .big);
    }
};

pub const Packet = struct {
    type: Type,
    /// Reception report count, SDES chunk count, or feedback message type (FMT).
    count: u5,
    /// The packet after the 4-byte header.
    body: []const u8,

    pub fn senderSsrc(p: Packet) u32 {
        return if (p.body.len >= 4) std.mem.readInt(u32, p.body[0..4], .big) else 0;
    }

    /// Media source SSRC for RTPFB/PSFB.
    pub fn mediaSsrc(p: Packet) u32 {
        return if (p.body.len >= 8) std.mem.readInt(u32, p.body[4..8], .big) else 0;
    }

    pub const SenderInfo = struct { ntp: u64, rtp_ts: u32, packets: u32, octets: u32 };

    pub fn senderInfo(p: Packet) ?SenderInfo {
        if (p.type != .sr or p.body.len < 24) return null;
        return .{
            .ntp = std.mem.readInt(u64, p.body[4..12], .big),
            .rtp_ts = std.mem.readInt(u32, p.body[12..16], .big),
            .packets = std.mem.readInt(u32, p.body[16..20], .big),
            .octets = std.mem.readInt(u32, p.body[20..24], .big),
        };
    }

    pub fn reportBlock(p: Packet, i: usize) ?ReportBlock {
        const start: usize = if (p.type == .sr) 24 else if (p.type == .rr) 4 else return null;
        const at = start + 24 * i;
        if (i >= p.count or at + 24 > p.body.len) return null;
        return ReportBlock.read(p.body[at..][0..24]);
    }

    pub fn isNack(p: Packet) bool {
        return p.type == .rtpfb and p.count == 1;
    }

    pub fn isPli(p: Packet) bool {
        return p.type == .psfb and p.count == 1;
    }

    pub fn isFir(p: Packet) bool {
        return p.type == .psfb and p.count == 4;
    }

    /// For FIR the media SSRC sits in the FCI.
    pub fn firTarget(p: Packet) ?u32 {
        if (!p.isFir() or p.body.len < 12) return null;
        return std.mem.readInt(u32, p.body[8..12], .big);
    }

    /// Expands NACK PID/BLP pairs into `out`.
    pub fn nackList(p: Packet, out: []u16) []u16 {
        var n: usize = 0;
        var i: usize = 8;
        while (i + 4 <= p.body.len) : (i += 4) {
            const pid = std.mem.readInt(u16, p.body[i..][0..2], .big);
            const blp = std.mem.readInt(u16, p.body[i + 2 ..][0..2], .big);
            if (n < out.len) {
                out[n] = pid;
                n += 1;
            }
            for (0..16) |bit| if (blp & (@as(u16, 1) << @intCast(bit)) != 0 and n < out.len) {
                out[n] = pid +% @as(u16, @intCast(bit + 1));
                n += 1;
            };
        }
        return out[0..n];
    }

    pub fn rembBitrate(p: Packet) ?u64 {
        if (p.type != .psfb or p.count != 15 or p.body.len < 16 or !std.mem.eql(u8, p.body[8..12], "REMB")) return null;
        const exp: u6 = @intCast(p.body[13] >> 2);
        const mantissa: u64 = (@as(u64, p.body[13] & 3) << 16) | std.mem.readInt(u16, p.body[14..16], .big);
        return mantissa << exp;
    }
};

pub const Iterator = struct {
    data: []const u8,
    pos: usize = 0,

    pub fn next(it: *Iterator) ?Packet {
        if (it.pos + 4 > it.data.len) return null;
        const h = it.data[it.pos..];
        if (h[0] >> 6 != 2) return null;
        const len = 4 + 4 * @as(usize, std.mem.readInt(u16, h[2..4], .big));
        if (len > h.len) return null;
        it.pos += len;
        var body = h[4..len];
        if (h[0] & 0x20 != 0 and body.len > 0) body = body[0 .. body.len -| body[body.len - 1]];
        return .{ .type = @enumFromInt(h[1]), .count = @truncate(h[0]), .body = body };
    }
};

/// NTP timestamp (RFC 3550 4) from Unix milliseconds.
pub fn ntpFromUnixMs(ms: u64) u64 {
    const secs = ms / 1000 + 2_208_988_800;
    const frac = ((ms % 1000) << 32) / 1000;
    return (secs << 32) | frac;
}

const testing = std.testing;

test "compound SR + SDES + REMB + NACK + PLI round trip" {
    var buf: [512]u8 = undefined;
    var b: Builder = .{ .buf = &buf };
    try b.senderReport(0x11111111, ntpFromUnixMs(1_700_000_000_123), 48000, 10, 1000, &.{.{ .ssrc = 0x22222222, .fraction_lost = 3, .highest_seq = 77 }});
    try b.sdesCname(0x11111111, "abc");
    try b.remb(0x11111111, 1_500_000, &.{0x22222222});
    try b.nack(0x11111111, 0x22222222, &.{ 10, 11, 13, 40 });
    try b.pli(0x11111111, 0x22222222);
    try b.fir(0x11111111, 0x33333333, 1);

    var it: Iterator = .{ .data = b.bytes() };
    const sr = it.next().?;
    try testing.expectEqual(Type.sr, sr.type);
    try testing.expectEqual(@as(u32, 48000), sr.senderInfo().?.rtp_ts);
    try testing.expectEqual(@as(u32, 77), sr.reportBlock(0).?.highest_seq);
    try testing.expectEqual(Type.sdes, it.next().?.type);
    const remb = it.next().?;
    const rate = remb.rembBitrate().?;
    try testing.expect(rate <= 1_500_000 and rate > 1_490_000);
    const nack = it.next().?;
    try testing.expect(nack.isNack());
    var lost: [32]u16 = undefined;
    try testing.expectEqualSlices(u16, &.{ 10, 11, 13, 40 }, nack.nackList(&lost));
    const pli = it.next().?;
    try testing.expect(pli.isPli());
    try testing.expectEqual(@as(u32, 0x22222222), pli.mediaSsrc());
    try testing.expectEqual(@as(?u32, 0x33333333), it.next().?.firTarget());
    try testing.expect(it.next() == null);
}
