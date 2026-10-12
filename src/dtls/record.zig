//! DTLS 1.2 record layer (RFC 6347 4.1): headers, AES-128-GCM protection (RFC 5288) and the
//! anti-replay window (RFC 6347 4.1.2.6).

const std = @import("std");

const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

pub const header_len = 13;
pub const version_dtls12: u16 = 0xFEFD;
pub const version_dtls10: u16 = 0xFEFF;
/// Explicit nonce (8) + GCM tag (16).
pub const aead_overhead = 24;

pub const ContentType = enum(u8) {
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,
    _,
};

pub const Record = struct {
    content_type: ContentType,
    version: u16,
    epoch: u16,
    seq: u64, // 48 bits
    fragment: []const u8,
};

/// Splits a datagram into records. Stops (returning null) on malformed trailing data,
/// which per RFC 6347 4.1.2.7 is silently discarded.
pub const Iterator = struct {
    data: []const u8,
    pos: usize = 0,

    pub fn next(it: *Iterator) ?Record {
        if (it.pos + header_len > it.data.len) return null;
        const h = it.data[it.pos..];
        const len = std.mem.readInt(u16, h[11..13], .big);
        if (header_len + len > h.len) return null;
        it.pos += header_len + len;
        return .{
            .content_type = @enumFromInt(h[0]),
            .version = std.mem.readInt(u16, h[1..3], .big),
            .epoch = std.mem.readInt(u16, h[3..5], .big),
            .seq = std.mem.readInt(u48, h[5..11], .big),
            .fragment = h[header_len..][0..len],
        };
    }
};

pub fn writeHeader(out: *[header_len]u8, ct: ContentType, epoch: u16, seq: u64, len: usize) void {
    out[0] = @intFromEnum(ct);
    std.mem.writeInt(u16, out[1..3], version_dtls12, .big);
    std.mem.writeInt(u16, out[3..5], epoch, .big);
    std.mem.writeInt(u48, out[5..11], @intCast(seq), .big);
    std.mem.writeInt(u16, out[11..13], @intCast(len), .big);
}

/// One direction's AES-128-GCM state for epoch 1.
pub const Cipher = struct {
    key: [16]u8,
    salt: [4]u8,

    fn aad(epoch: u16, seq: u64, ct: ContentType, len: usize) [13]u8 {
        var a: [13]u8 = undefined;
        std.mem.writeInt(u16, a[0..2], epoch, .big);
        std.mem.writeInt(u48, a[2..8], @intCast(seq), .big);
        a[8] = @intFromEnum(ct);
        std.mem.writeInt(u16, a[9..11], version_dtls12, .big);
        std.mem.writeInt(u16, a[11..13], @intCast(len), .big);
        return a;
    }

    /// Writes header + explicit nonce + ciphertext + tag into `out`; returns the record length.
    pub fn seal(c: *const Cipher, out: []u8, ct: ContentType, epoch: u16, seq: u64, plaintext: []const u8) usize {
        const len = 8 + plaintext.len + 16;
        writeHeader(out[0..header_len], ct, epoch, seq, len);
        const explicit = out[header_len..][0..8];
        std.mem.writeInt(u16, explicit[0..2], epoch, .big);
        std.mem.writeInt(u48, explicit[2..8], @intCast(seq), .big);
        var nonce: [12]u8 = undefined;
        nonce[0..4].* = c.salt;
        nonce[4..12].* = explicit.*;
        const body = out[header_len + 8 ..][0..plaintext.len];
        var tag: [16]u8 = undefined;
        Aes128Gcm.encrypt(body, &tag, plaintext, &aad(epoch, seq, ct, plaintext.len), nonce, c.key);
        out[header_len + 8 + plaintext.len ..][0..16].* = tag;
        return header_len + len;
    }

    /// Decrypts a record fragment into `out`; returns the plaintext.
    pub fn open(c: *const Cipher, out: []u8, rec: Record) ![]u8 {
        if (rec.fragment.len < aead_overhead) return error.Truncated;
        const n = rec.fragment.len - aead_overhead;
        if (out.len < n) return error.NoSpaceLeft;
        var nonce: [12]u8 = undefined;
        nonce[0..4].* = c.salt;
        nonce[4..12].* = rec.fragment[0..8].*;
        Aes128Gcm.decrypt(out[0..n], rec.fragment[8..][0..n], rec.fragment[8 + n ..][0..16].*, &aad(rec.epoch, rec.seq, rec.content_type, n), nonce, c.key) catch
            return error.BadRecordMac;
        return out[0..n];
    }
};

/// 64-record sliding window over sequence numbers of one epoch.
pub const ReplayWindow = struct {
    top: u64 = 0,
    bits: u64 = 0,
    any: bool = false,

    pub fn check(w: *const ReplayWindow, seq: u64) bool {
        if (!w.any or seq > w.top) return true;
        const back = w.top - seq;
        return back < 64 and (w.bits >> @intCast(back)) & 1 == 0;
    }

    pub fn accept(w: *ReplayWindow, seq: u64) void {
        if (!w.any) {
            w.* = .{ .top = seq, .bits = 1, .any = true };
        } else if (seq > w.top) {
            const shift = seq - w.top;
            w.bits = if (shift >= 64) 1 else (w.bits << @intCast(shift)) | 1;
            w.top = seq;
        } else {
            w.bits |= @as(u64, 1) << @intCast(w.top - seq);
        }
    }
};

test "seal/open round trip and tamper" {
    const c: Cipher = .{ .key = @splat(7), .salt = .{ 1, 2, 3, 4 } };
    var buf: [128]u8 = undefined;
    const n = c.seal(&buf, .application_data, 1, 5, "hello");
    var it: Iterator = .{ .data = buf[0..n] };
    const rec = it.next().?;
    try std.testing.expectEqual(@as(u64, 5), rec.seq);
    var out: [64]u8 = undefined;
    try std.testing.expectEqualStrings("hello", try c.open(&out, rec));
    buf[20] ^= 1;
    it = .{ .data = buf[0..n] };
    try std.testing.expectError(error.BadRecordMac, c.open(&out, it.next().?));
}

test "replay window" {
    var w: ReplayWindow = .{};
    w.accept(3);
    w.accept(1);
    try std.testing.expect(!w.check(1));
    try std.testing.expect(w.check(2));
    w.accept(100);
    try std.testing.expect(!w.check(3));
}
