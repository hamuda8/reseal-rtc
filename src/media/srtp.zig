//! SRTP and SRTCP (RFC 3711) with AES_CM_128_HMAC_SHA1_80 and AEAD_AES_128_GCM (RFC 7714).
//!
//! A `Context` protects one direction. DTLS-SRTP gives each side a client and a server key;
//! the sender uses its own and the receiver the peer's (see `fromKeyingMaterial`).

const std = @import("std");

const Aes128 = std.crypto.core.aes.Aes128;
const AesCtx = @TypeOf(Aes128.initEnc(@as([16]u8, @splat(0))));
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const HmacSha1 = std.crypto.auth.hmac.HmacSha1;

/// DTLS-SRTP protection profile numbers (RFC 5764, RFC 7714).
pub const Profile = enum(u16) {
    aes128_cm_sha1_80 = 0x0001,
    aead_aes128_gcm = 0x0007,

    pub fn keyLen(_: Profile) usize {
        return 16;
    }

    pub fn saltLen(p: Profile) usize {
        return switch (p) {
            .aes128_cm_sha1_80 => 14,
            .aead_aes128_gcm => 12,
        };
    }

    /// Bytes the sender appends to every RTP packet (auth tag).
    pub fn rtpOverhead(p: Profile) usize {
        return switch (p) {
            .aes128_cm_sha1_80 => 10,
            .aead_aes128_gcm => 16,
        };
    }

    /// Bytes appended to every RTCP packet (index word + tag).
    pub fn rtcpOverhead(p: Profile) usize {
        return 4 + p.rtpOverhead();
    }

    /// Bytes of DTLS exporter output needed for both directions (RFC 5764 4.2).
    pub fn keyingMaterialLen(p: Profile) usize {
        return 2 * (p.keyLen() + p.saltLen());
    }

    pub fn fromInt(v: u16) ?Profile {
        return std.enums.fromInt(Profile, v);
    }
};

const label = struct {
    const rtp_encryption = 0;
    const rtp_auth = 1;
    const rtp_salt = 2;
    const rtcp_encryption = 3;
    const rtcp_auth = 4;
    const rtcp_salt = 5;
};

/// The AES-CM PRF of RFC 3711 4.3.3 with key_derivation_rate 0: AES-CTR over
/// (master_salt XOR label at byte 7), the salt left-aligned in a zero block.
pub fn deriveKey(master_key: [16]u8, master_salt: []const u8, l: u8, out: []u8) void {
    var iv: [16]u8 = @splat(0);
    @memcpy(iv[0..master_salt.len], master_salt);
    iv[7] ^= l;
    keystream(Aes128.initEnc(master_key), iv, out);
}

/// AES in counter mode, counter in the low bits of `iv`, written over zeros.
fn keystream(ctx: AesCtx, iv: [16]u8, out: []u8) void {
    @memset(out, 0);
    std.crypto.core.modes.ctr(AesCtx, ctx, out, out, iv, .big);
}

fn xorKeystream(ctx: AesCtx, iv: [16]u8, data: []u8) void {
    std.crypto.core.modes.ctr(AesCtx, ctx, data, data, iv, .big);
}

const SessionKeys = struct {
    enc_key: [16]u8,
    enc: AesCtx,
    salt: [14]u8, // GCM uses the first 12
    auth: [20]u8,

    fn derive(profile: Profile, master_key: [16]u8, master_salt: []const u8, rtcp: bool) SessionKeys {
        const base: u8 = if (rtcp) 3 else 0;
        var k: SessionKeys = undefined;
        deriveKey(master_key, master_salt, base + label.rtp_encryption, &k.enc_key);
        k.enc = Aes128.initEnc(k.enc_key);
        k.salt = @splat(0);
        deriveKey(master_key, master_salt, base + label.rtp_salt, k.salt[0..profile.saltLen()]);
        k.auth = @splat(0);
        if (profile == .aes128_cm_sha1_80) deriveKey(master_key, master_salt, base + label.rtp_auth, &k.auth);
        return k;
    }

    fn direct(enc_key: [16]u8, salt: []const u8, auth: [20]u8) SessionKeys {
        var k: SessionKeys = .{ .enc_key = enc_key, .enc = Aes128.initEnc(enc_key), .salt = @splat(0), .auth = auth };
        @memcpy(k.salt[0..salt.len], salt);
        return k;
    }
};

/// A 128-entry sliding window over packet indexes (RFC 3711 3.3.2).
const ReplayWindow = struct {
    top: u64 = 0,
    bits: u128 = 0,
    any: bool = false,

    fn check(w: *const ReplayWindow, index: u64) bool {
        if (!w.any or index > w.top) return true;
        const back = w.top - index;
        if (back >= 128) return false;
        return (w.bits >> @intCast(back)) & 1 == 0;
    }

    fn accept(w: *ReplayWindow, index: u64) void {
        if (!w.any) {
            w.* = .{ .top = index, .bits = 1, .any = true };
        } else if (index > w.top) {
            const shift = index - w.top;
            w.bits = if (shift >= 128) 1 else (w.bits << @intCast(shift)) | 1;
            w.top = index;
        } else {
            w.bits |= @as(u128, 1) << @intCast(w.top - index);
        }
    }
};

const Stream = struct {
    ssrc: u32,
    roc: u32 = 0,
    s_l: u16 = 0,
    seen: bool = false,
    replay: ReplayWindow = .{},
    rtcp_replay: ReplayWindow = .{},
    srtcp_index: u32 = 0, // next index to send
};

pub const Error = error{ Truncated, AuthenticationFailed, Replayed, NoSpaceLeft, TooManyStreams };

const max_streams = 64;

pub const Context = struct {
    profile: Profile,
    rtp: SessionKeys,
    rtcp: SessionKeys,
    streams: [max_streams]Stream = undefined,
    stream_count: usize = 0,

    pub fn init(profile: Profile, master_key: [16]u8, master_salt: []const u8) Context {
        std.debug.assert(master_salt.len == profile.saltLen());
        return .{
            .profile = profile,
            .rtp = SessionKeys.derive(profile, master_key, master_salt, false),
            .rtcp = SessionKeys.derive(profile, master_key, master_salt, true),
        };
    }

    /// Splits DTLS exporter output (client key, server key, client salt, server salt) into the
    /// local (send) and remote (receive) contexts.
    pub fn fromKeyingMaterial(profile: Profile, material: []const u8, is_dtls_client: bool) struct { send: Context, recv: Context } {
        const kl = profile.keyLen();
        const sl = profile.saltLen();
        const client_key = material[0..kl];
        const server_key = material[kl .. 2 * kl];
        const client_salt = material[2 * kl .. 2 * kl + sl];
        const server_salt = material[2 * kl + sl .. 2 * kl + 2 * sl];
        const client = Context.init(profile, client_key[0..16].*, client_salt);
        const server = Context.init(profile, server_key[0..16].*, server_salt);
        return if (is_dtls_client) .{ .send = client, .recv = server } else .{ .send = server, .recv = client };
    }

    fn stream(c: *Context, ssrc: u32) Error!*Stream {
        for (c.streams[0..c.stream_count]) |*s| if (s.ssrc == ssrc) return s;
        if (c.stream_count == max_streams) return error.TooManyStreams;
        c.streams[c.stream_count] = .{ .ssrc = ssrc };
        c.stream_count += 1;
        return &c.streams[c.stream_count - 1];
    }

    // ---- SRTP ------------------------------------------------------------------------------

    /// Encrypts and authenticates the RTP packet in `buf[0..len]` in place. `buf` needs
    /// `profile.rtpOverhead()` spare bytes. Returns the protected length.
    pub fn protectRtp(c: *Context, buf: []u8, len: usize) Error!usize {
        const hl = try rtpHeaderLen(buf[0..len]);
        if (len + c.profile.rtpOverhead() > buf.len) return error.NoSpaceLeft;
        const ssrc = std.mem.readInt(u32, buf[8..12], .big);
        const seq = std.mem.readInt(u16, buf[2..4], .big);
        const s = try c.stream(ssrc);
        const roc = estimateRoc(s, seq);
        updateRoc(s, roc, seq);
        switch (c.profile) {
            .aes128_cm_sha1_80 => {
                xorKeystream(c.rtp.enc, cmIv(c.rtp.salt, ssrc, (@as(u64, roc) << 16) | seq), buf[hl..len]);
                var tag: [20]u8 = undefined;
                rtpAuthTag(&c.rtp.auth, buf[0..len], roc, &tag);
                @memcpy(buf[len..][0..10], tag[0..10]);
                return len + 10;
            },
            .aead_aes128_gcm => {
                const iv = gcmRtpIv(c.rtp.salt[0..12].*, ssrc, roc, seq);
                var tag: [16]u8 = undefined;
                Aes128Gcm.encrypt(buf[hl..len], &tag, buf[hl..len], buf[0..hl], iv, c.rtp.enc_key);
                @memcpy(buf[len..][0..16], &tag);
                return len + 16;
            },
        }
    }

    /// Verifies and decrypts the SRTP packet in place; returns the RTP length.
    pub fn unprotectRtp(c: *Context, buf: []u8) Error!usize {
        const overhead = c.profile.rtpOverhead();
        if (buf.len < 12 + overhead) return error.Truncated;
        const len = buf.len - overhead;
        const hl = try rtpHeaderLen(buf[0..len]);
        const ssrc = std.mem.readInt(u32, buf[8..12], .big);
        const seq = std.mem.readInt(u16, buf[2..4], .big);
        const s = try c.stream(ssrc);
        const roc = estimateRoc(s, seq);
        const index = (@as(u64, roc) << 16) | seq;
        if (!s.replay.check(index)) return error.Replayed;
        switch (c.profile) {
            .aes128_cm_sha1_80 => {
                var tag: [20]u8 = undefined;
                rtpAuthTag(&c.rtp.auth, buf[0..len], roc, &tag);
                if (!std.crypto.timing_safe.eql([10]u8, tag[0..10].*, buf[len..][0..10].*)) return error.AuthenticationFailed;
                xorKeystream(c.rtp.enc, cmIv(c.rtp.salt, ssrc, index), buf[hl..len]);
            },
            .aead_aes128_gcm => {
                const iv = gcmRtpIv(c.rtp.salt[0..12].*, ssrc, roc, seq);
                Aes128Gcm.decrypt(buf[hl..len], buf[hl..len], buf[len..][0..16].*, buf[0..hl], iv, c.rtp.enc_key) catch
                    return error.AuthenticationFailed;
            },
        }
        s.replay.accept(index);
        updateRoc(s, roc, seq);
        return len;
    }

    // ---- SRTCP -----------------------------------------------------------------------------

    /// Protects the RTCP compound packet in `buf[0..len]` in place; needs
    /// `profile.rtcpOverhead()` spare bytes.
    pub fn protectRtcp(c: *Context, buf: []u8, len: usize) Error!usize {
        if (len < 8) return error.Truncated;
        const ssrc = std.mem.readInt(u32, buf[4..8], .big);
        const s = try c.stream(ssrc);
        const index = s.srtcp_index;
        s.srtcp_index = (s.srtcp_index + 1) & 0x7fff_ffff;
        return c.protectRtcpIndex(buf, len, index);
    }

    fn protectRtcpIndex(c: *Context, buf: []u8, len: usize, index: u32) Error!usize {
        if (len + c.profile.rtcpOverhead() > buf.len) return error.NoSpaceLeft;
        const ssrc = std.mem.readInt(u32, buf[4..8], .big);
        const e_index: u32 = 0x8000_0000 | index;
        switch (c.profile) {
            .aes128_cm_sha1_80 => {
                xorKeystream(c.rtcp.enc, cmIv(c.rtcp.salt, ssrc, index), buf[8..len]);
                std.mem.writeInt(u32, buf[len..][0..4], e_index, .big);
                var tag: [20]u8 = undefined;
                HmacSha1.create(&tag, buf[0 .. len + 4], &c.rtcp.auth);
                @memcpy(buf[len + 4 ..][0..10], tag[0..10]);
                return len + 14;
            },
            .aead_aes128_gcm => {
                var aad: [12]u8 = undefined;
                @memcpy(aad[0..8], buf[0..8]);
                std.mem.writeInt(u32, aad[8..12], e_index, .big);
                var tag: [16]u8 = undefined;
                Aes128Gcm.encrypt(buf[8..len], &tag, buf[8..len], &aad, gcmRtcpIv(c.rtcp.salt[0..12].*, ssrc, index), c.rtcp.enc_key);
                @memcpy(buf[len..][0..16], &tag);
                std.mem.writeInt(u32, buf[len + 16 ..][0..4], e_index, .big);
                return len + 20;
            },
        }
    }

    /// Verifies and decrypts an SRTCP packet in place; returns the RTCP length.
    pub fn unprotectRtcp(c: *Context, buf: []u8) Error!usize {
        const overhead = c.profile.rtcpOverhead();
        if (buf.len < 8 + overhead) return error.Truncated;
        const ssrc = std.mem.readInt(u32, buf[4..8], .big);
        const s = try c.stream(ssrc);
        switch (c.profile) {
            .aes128_cm_sha1_80 => {
                const len = buf.len - 14;
                const e_index = std.mem.readInt(u32, buf[len..][0..4], .big);
                const index = e_index & 0x7fff_ffff;
                if (!s.rtcp_replay.check(index)) return error.Replayed;
                var tag: [20]u8 = undefined;
                HmacSha1.create(&tag, buf[0 .. len + 4], &c.rtcp.auth);
                if (!std.crypto.timing_safe.eql([10]u8, tag[0..10].*, buf[len + 4 ..][0..10].*)) return error.AuthenticationFailed;
                if (e_index & 0x8000_0000 != 0) xorKeystream(c.rtcp.enc, cmIv(c.rtcp.salt, ssrc, index), buf[8..len]);
                s.rtcp_replay.accept(index);
                return len;
            },
            .aead_aes128_gcm => {
                const len = buf.len - 20;
                const e_index = std.mem.readInt(u32, buf[len + 16 ..][0..4], .big);
                const index = e_index & 0x7fff_ffff;
                if (!s.rtcp_replay.check(index)) return error.Replayed;
                var aad: [12]u8 = undefined;
                @memcpy(aad[0..8], buf[0..8]);
                std.mem.writeInt(u32, aad[8..12], e_index, .big);
                // E=0 (authentication only) is not used by browsers; treat it as an error.
                if (e_index & 0x8000_0000 == 0) return error.AuthenticationFailed;
                Aes128Gcm.decrypt(buf[8..len], buf[8..len], buf[len..][0..16].*, &aad, gcmRtcpIv(c.rtcp.salt[0..12].*, ssrc, index), c.rtcp.enc_key) catch
                    return error.AuthenticationFailed;
                s.rtcp_replay.accept(index);
                return len;
            },
        }
    }
};

/// Header length including CSRCs and the extension, so payload encryption starts after it.
pub fn rtpHeaderLen(pkt: []const u8) Error!usize {
    if (pkt.len < 12) return error.Truncated;
    var hl: usize = 12 + 4 * @as(usize, pkt[0] & 0x0f);
    if (pkt[0] & 0x10 != 0) {
        if (pkt.len < hl + 4) return error.Truncated;
        hl += 4 + 4 * @as(usize, std.mem.readInt(u16, pkt[hl + 2 ..][0..2], .big));
    }
    if (hl > pkt.len) return error.Truncated;
    return hl;
}

/// RFC 3711 3.3.1: guess the rollover counter for `seq` given the highest seen sequence.
fn estimateRoc(s: *const Stream, seq: u16) u32 {
    if (!s.seen) return s.roc;
    if (s.s_l < 32768) {
        if (seq > s.s_l and seq - s.s_l > 32768) return s.roc -% 1;
        return s.roc;
    }
    if (s.s_l - 32768 > seq) return s.roc +% 1;
    return s.roc;
}

fn updateRoc(s: *Stream, roc: u32, seq: u16) void {
    if (!s.seen) {
        s.seen = true;
        s.roc = roc;
        s.s_l = seq;
        return;
    }
    if (roc == s.roc +% 1) {
        s.roc = roc;
        s.s_l = seq;
    } else if (roc == s.roc and seq > s.s_l) {
        s.s_l = seq;
    }
}

/// AES-CM IV: (salt * 2^16) XOR (SSRC * 2^64) XOR (index * 2^16).
fn cmIv(salt: [14]u8, ssrc: u32, index: u64) [16]u8 {
    var iv: [16]u8 = @splat(0);
    @memcpy(iv[0..14], &salt);
    var s: [4]u8 = undefined;
    std.mem.writeInt(u32, &s, ssrc, .big);
    for (0..4) |i| iv[4 + i] ^= s[i];
    var idx: [8]u8 = undefined;
    std.mem.writeInt(u64, &idx, index, .big);
    for (0..6) |i| iv[8 + i] ^= idx[2 + i];
    return iv;
}

fn rtpAuthTag(key: *const [20]u8, pkt: []const u8, roc: u32, out: *[20]u8) void {
    var mac = HmacSha1.init(key);
    mac.update(pkt);
    var r: [4]u8 = undefined;
    std.mem.writeInt(u32, &r, roc, .big);
    mac.update(&r);
    mac.final(out);
}

fn gcmRtpIv(salt: [12]u8, ssrc: u32, roc: u32, seq: u16) [12]u8 {
    var iv: [12]u8 = @splat(0);
    std.mem.writeInt(u32, iv[2..6], ssrc, .big);
    std.mem.writeInt(u32, iv[6..10], roc, .big);
    std.mem.writeInt(u16, iv[10..12], seq, .big);
    for (&iv, salt) |*b, k| b.* ^= k;
    return iv;
}

fn gcmRtcpIv(salt: [12]u8, ssrc: u32, index: u32) [12]u8 {
    var iv: [12]u8 = @splat(0);
    std.mem.writeInt(u32, iv[2..6], ssrc, .big);
    std.mem.writeInt(u32, iv[8..12], index, .big);
    for (&iv, salt) |*b, k| b.* ^= k;
    return iv;
}

// ---- tests -------------------------------------------------------------------------------

const testing = std.testing;

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "RFC 3711 B.2 AES-CM keystream" {
    const ctx = Aes128.initEnc(hex("2B7E151628AED2A6ABF7158809CF4F3C"));
    var ks: [48]u8 = undefined;
    keystream(ctx, hex("F0F1F2F3F4F5F6F7F8F9FAFBFCFD0000"), &ks);
    try testing.expectEqualSlices(u8, &hex("E03EAD0935C95E80E166B16DD92B4EB4" ++
        "D23513162B02D0F72A43A2FE4A5F97AB" ++ "41E95B3BB0A2E8DD477901E4FCA894C0"), &ks);
    // The end of the 65282-block segment.
    var tail: [48]u8 = undefined;
    keystream(ctx, hex("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF"), &tail);
    try testing.expectEqualSlices(u8, &hex("EC8CDF7398607CB0F2D21675EA9EA1E4" ++
        "362B7C3C6773516318A077D7FC5073AE" ++ "6A2CC3787889374FBEB4C81B17BA6C44"), &tail);
}

test "RFC 3711 B.3 key derivation" {
    const key = hex("E1F97A0D3E018BE0D64FA32C06DE4139");
    const salt = hex("0EC675AD498AFEEBB6960B3AABE6");
    var cipher_key: [16]u8 = undefined;
    deriveKey(key, &salt, label.rtp_encryption, &cipher_key);
    try testing.expectEqualSlices(u8, &hex("C61E7A93744F39EE10734AFE3FF7A087"), &cipher_key);
    var cipher_salt: [14]u8 = undefined;
    deriveKey(key, &salt, label.rtp_salt, &cipher_salt);
    try testing.expectEqualSlices(u8, &hex("30CBBC08863D8C85D49DB34A9AE1"), &cipher_salt);
    var auth: [94]u8 = undefined;
    deriveKey(key, &salt, label.rtp_auth, &auth);
    try testing.expectEqualSlices(u8, &hex("CEBE321F6FF7716B6FD4AB49AF256A15" ++ "6D38BAA48F0A0ACF3C34E2359E6CDBCE" ++
        "E049646C43D9327AD175578EF7227098" ++ "6371C10C9A369AC2F94A8C5FBCDDDC25" ++
        "6D6E919A48B610EF17C2041E47403576" ++ "6B68642C59BBFC2F34DB60DBDFB2"), &auth);
}

fn gcmTestContext() Context {
    const keys = SessionKeys.direct(hex("000102030405060708090a0b0c0d0e0f"), &hex("517569642070726f2071756f"), @splat(0));
    return .{ .profile = .aead_aes128_gcm, .rtp = keys, .rtcp = keys };
}

const gcm_rtp_plain = hex("8040f17b8041f8d35501a0b2" ++ "47616c6c696120657374206f6d6e697320646976" ++
    "69736120696e207061727465732074726573");
const gcm_rtp_cipher = hex("8040f17b8041f8d35501a0b2f24de3a3fb34de6cacba861c9d7e4bcabe633bd5" ++
    "0d294e6f42a5f47a51c7d19b36de3adf8833899d7f27beb16a9152cf765ee4390cce");

test "RFC 7714 16.1.1 SRTP AEAD_AES_128_GCM encryption and 16.1.2 decryption" {
    var tx = gcmTestContext();
    var buf: [128]u8 = undefined;
    @memcpy(buf[0..gcm_rtp_plain.len], &gcm_rtp_plain);
    const n = try tx.protectRtp(&buf, gcm_rtp_plain.len);
    try testing.expectEqualSlices(u8, &gcm_rtp_cipher, buf[0..n]);

    var rx = gcmTestContext();
    const m = try rx.unprotectRtp(buf[0..n]);
    try testing.expectEqualSlices(u8, &gcm_rtp_plain, buf[0..m]);
    // The same packet again is a replay.
    @memcpy(buf[0..gcm_rtp_cipher.len], &gcm_rtp_cipher);
    try testing.expectError(error.Replayed, rx.unprotectRtp(buf[0..gcm_rtp_cipher.len]));
}

test "RFC 7714 17.1 SRTCP AEAD_AES_128_GCM encryption and tagging" {
    const plain = hex("81c8000d4d6172734e5450314e545032525450200000042a0000e9304c756e61" ++
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    const want = hex("81c8000d4d61727363e94885dcdab67ca727d7662f6b7e997ff5c0f76c06f32d" ++
        "c676a5f1730d6fda4ce09b4686303ded0bb9275bc84aa45896cf4d2fc5abf87245d9eade800005d4");
    var tx = gcmTestContext();
    var buf: [128]u8 = undefined;
    @memcpy(buf[0..plain.len], &plain);
    const n = try tx.protectRtcpIndex(&buf, plain.len, 0x5d4);
    try testing.expectEqualSlices(u8, &want, buf[0..n]);
    var rx = gcmTestContext();
    const m = try rx.unprotectRtcp(buf[0..n]);
    try testing.expectEqualSlices(u8, &plain, buf[0..m]);
}

test "AES-CM-80 round trip, tamper detection and rollover" {
    const key = hex("E1F97A0D3E018BE0D64FA32C06DE4139");
    const salt = hex("0EC675AD498AFEEBB6960B3AABE6");
    var tx = Context.init(.aes128_cm_sha1_80, key, &salt);
    var rx = Context.init(.aes128_cm_sha1_80, key, &salt);
    var seq: u16 = 65530;
    for (0..20) |_| {
        var buf: [64]u8 = undefined;
        const pkt = hex("800f1234decafbadcafebabe") ++ hex("abababababababababababababababab");
        @memcpy(buf[0..pkt.len], &pkt);
        std.mem.writeInt(u16, buf[2..4], seq, .big);
        const n = try tx.protectRtp(&buf, pkt.len);
        try testing.expect(!std.mem.eql(u8, buf[12..28], pkt[12..28]));
        var bad = buf;
        bad[20] ^= 1;
        try testing.expectError(error.AuthenticationFailed, rx.unprotectRtp(bad[0..n]));
        const m = try rx.unprotectRtp(buf[0..n]);
        try testing.expectEqualSlices(u8, pkt[12..], buf[12..m]);
        seq +%= 1;
    }
    try testing.expectEqual(@as(u32, 1), rx.streams[0].roc);

    var rbuf: [64]u8 = undefined;
    const rtcp = hex("80c80006cafebabe0000000100000002000000030000000400000005");
    @memcpy(rbuf[0..rtcp.len], &rtcp);
    const n = try tx.protectRtcp(&rbuf, rtcp.len);
    const m = try rx.unprotectRtcp(rbuf[0..n]);
    try testing.expectEqualSlices(u8, &rtcp, rbuf[0..m]);
}

test "replay window" {
    var w: ReplayWindow = .{};
    w.accept(10);
    try testing.expect(!w.check(10));
    try testing.expect(w.check(9));
    w.accept(200);
    try testing.expect(!w.check(10)); // too old
    try testing.expect(w.check(199));
}
