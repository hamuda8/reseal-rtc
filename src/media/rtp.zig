//! RTP packets (RFC 3550 5.1): parsing and writing the fixed header, CSRCs and the header
//! extension (RFC 8285 one-byte form when we write one).

const std = @import("std");

pub const Packet = struct {
    marker: bool,
    payload_type: u7,
    seq: u16,
    timestamp: u32,
    ssrc: u32,
    csrc_count: u4 = 0,
    /// Raw extension block (after the 4-byte extension header), if any.
    extension: ?[]const u8 = null,
    extension_profile: u16 = 0,
    payload: []const u8,
    header_len: usize = 12,

    pub fn parse(data: []const u8) !Packet {
        if (data.len < 12 or data[0] >> 6 != 2) return error.NotRtp;
        var p: Packet = .{
            .marker = data[1] & 0x80 != 0,
            .payload_type = @truncate(data[1]),
            .seq = std.mem.readInt(u16, data[2..4], .big),
            .timestamp = std.mem.readInt(u32, data[4..8], .big),
            .ssrc = std.mem.readInt(u32, data[8..12], .big),
            .csrc_count = @truncate(data[0]),
            .payload = &.{},
        };
        var hl: usize = 12 + 4 * @as(usize, p.csrc_count);
        if (data[0] & 0x10 != 0) {
            if (data.len < hl + 4) return error.Truncated;
            p.extension_profile = std.mem.readInt(u16, data[hl..][0..2], .big);
            const words = std.mem.readInt(u16, data[hl + 2 ..][0..2], .big);
            if (data.len < hl + 4 + 4 * @as(usize, words)) return error.Truncated;
            p.extension = data[hl + 4 ..][0 .. 4 * @as(usize, words)];
            hl += 4 + 4 * @as(usize, words);
        }
        if (hl > data.len) return error.Truncated;
        var end = data.len;
        if (data[0] & 0x20 != 0) {
            const pad = data[data.len - 1];
            if (pad == 0 or pad > data.len - hl) return error.BadPadding;
            end -= pad;
        }
        p.header_len = hl;
        p.payload = data[hl..end];
        return p;
    }

    /// Value of one-byte extension element `id` (RFC 8285 4.2), if present.
    pub fn extensionElement(p: Packet, id: u8) ?[]const u8 {
        const ext = p.extension orelse return null;
        if (p.extension_profile != 0xBEDE) return null;
        var i: usize = 0;
        while (i < ext.len) {
            const b = ext[i];
            if (b == 0) {
                i += 1;
                continue;
            }
            const eid = b >> 4;
            const len = @as(usize, b & 15) + 1;
            if (eid == 15 or i + 1 + len > ext.len) return null;
            if (eid == id) return ext[i + 1 ..][0..len];
            i += 1 + len;
        }
        return null;
    }
};

/// Writes a header without CSRCs or extension followed by `payload`; returns the length.
pub fn write(buf: []u8, marker: bool, pt: u7, seq: u16, timestamp: u32, ssrc: u32, payload: []const u8) !usize {
    if (buf.len < 12 + payload.len) return error.NoSpaceLeft;
    buf[0] = 0x80;
    buf[1] = @as(u8, pt) | (if (marker) @as(u8, 0x80) else 0);
    std.mem.writeInt(u16, buf[2..4], seq, .big);
    std.mem.writeInt(u32, buf[4..8], timestamp, .big);
    std.mem.writeInt(u32, buf[8..12], ssrc, .big);
    @memcpy(buf[12..][0..payload.len], payload);
    return 12 + payload.len;
}

/// RFC 5761 4: RTCP packet types 192..223 share the first byte range with RTP; tell them apart
/// by the second byte when rtcp-mux is in use.
pub fn isRtcp(data: []const u8) bool {
    return data.len >= 8 and data[1] >= 192 and data[1] <= 223;
}

/// Extends a 16-bit sequence number to 64 bits relative to the highest seen.
pub fn extendSeq(highest: u64, seq: u16) u64 {
    const base = highest & ~@as(u64, 0xffff);
    var candidate = base | seq;
    const diff: i64 = @as(i64, @intCast(candidate)) - @as(i64, @intCast(highest));
    if (diff > 32768 and candidate >= 0x10000) candidate -= 0x10000 else if (diff < -32768) candidate += 0x10000;
    return candidate;
}

test "parse and write" {
    var buf: [64]u8 = undefined;
    const n = try write(&buf, true, 111, 7, 960, 0xdeadbeef, "opus");
    const p = try Packet.parse(buf[0..n]);
    try std.testing.expect(p.marker);
    try std.testing.expectEqual(@as(u7, 111), p.payload_type);
    try std.testing.expectEqual(@as(u16, 7), p.seq);
    try std.testing.expectEqualStrings("opus", p.payload);
    try std.testing.expect(!isRtcp(buf[0..n]));
}

test "extension and padding" {
    // V=2 P=1 X=1, one-byte extension with id 4 (mid) = "0", 3 bytes padding.
    const pkt = [_]u8{ 0xB0, 0x60, 0, 1, 0, 0, 0, 1, 0, 0, 0, 2, 0xBE, 0xDE, 0, 1, 0x40, '0', 0, 0, 'h', 'i', 0, 0, 3 };
    const p = try Packet.parse(&pkt);
    try std.testing.expectEqualStrings("0", p.extensionElement(4).?);
    try std.testing.expectEqualStrings("hi", p.payload);
}

test "extend sequence across wrap" {
    try std.testing.expectEqual(@as(u64, 0x10002), extendSeq(0xfffe, 2));
    try std.testing.expectEqual(@as(u64, 0xfffe), extendSeq(0x10002, 0xfffe));
    try std.testing.expectEqual(@as(u64, 100), extendSeq(90, 100));
}
