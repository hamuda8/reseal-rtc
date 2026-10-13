//! A DTLS 1.2 connection (RFC 6347), client or server, as WebRTC uses it:
//! TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 with P-256 (or X25519) key exchange, mutual
//! certificate authentication against SDP fingerprints, use_srtp (RFC 5764), extended master
//! secret (RFC 7627) and the RFC 5705 exporter for SRTP keys.
//!
//! Sans-IO: feed datagrams with `handle`, call `poll` on timers, read `state`.
//! Session resumption, renegotiation and HelloVerifyRequest on the server side are not
//! implemented; ICE has already proven the peer's reachability before DTLS starts.

const std = @import("std");
const Conn = @This();

const record = @import("record.zig");
const hs = @import("handshake.zig");
const prf = @import("prf.zig");
const certs = @import("cert.zig");
const bytes = @import("bytes.zig");
const Profile = @import("../media/srtp.zig").Profile;

const Ecdsa = certs.Ecdsa;
const P256 = std.crypto.ecc.P256;
const X25519 = std.crypto.dh.X25519;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Role = enum { client, server };

pub const State = enum { new, handshaking, connected, closed, failed };

pub const Config = struct {
    role: Role,
    certificate: *const certs.Certificate,
    /// In preference order. Browsers offer GCM and CM; both are supported.
    srtp_profiles: []const Profile = &.{ .aead_aes128_gcm, .aes128_cm_sha1_80 },
    /// Largest datagram we send. 1200 keeps clear of IPv6 + TURN overhead.
    mtu: usize = 1200,
    initial_rto_ms: u64 = 400,
    max_retransmits: u32 = 8,
    /// Expected SHA-256 fingerprint of the peer certificate, from the remote SDP. May be set
    /// later with `setRemoteFingerprint`; the connection only reports `connected` once it matches.
    remote_fingerprint: ?certs.Fingerprint = null,
};

pub const Callbacks = struct {
    ctx: *anyopaque,
    send: *const fn (ctx: *anyopaque, datagram: []const u8) void,
    /// Decrypted application data (SCTP for data channels, later).
    data: ?*const fn (ctx: *anyopaque, data: []const u8) void = null,
};

const Step = enum {
    // client
    wait_server_hello,
    wait_certificate,
    wait_server_key_exchange,
    wait_certificate_request_or_done,
    wait_server_hello_done,
    wait_server_finished,
    // server
    wait_client_hello,
    wait_client_certificate,
    wait_client_key_exchange,
    wait_certificate_verify,
    wait_client_finished,
    // both
    done,
};

const FlightItem = struct {
    content_type: record.ContentType,
    epoch: u16,
    data: []u8, // a whole handshake message, or the CCS byte
};

const Ecdhe = union(enum) {
    none,
    p256: Ecdsa.KeyPair,
    x25519: X25519.KeyPair,
};

gpa: std.mem.Allocator,
io: std.Io,
config: Config,
cb: Callbacks,

state: State = .new,
step: Step,
failure: ?anyerror = null,

client_random: [32]u8 = undefined,
server_random: [32]u8 = undefined,
cookie: [255]u8 = undefined,
cookie_len: usize = 0,
transcript: std.ArrayList(u8) = .empty,
reasm: hs.Reassembler = .{},
next_send_seq: u16 = 0,

write_epoch: u16 = 0,
write_seq: [2]u64 = .{ 0, 0 },
write_cipher: ?record.Cipher = null,
pending_write_cipher: ?record.Cipher = null,
read_cipher: ?record.Cipher = null,
replay: record.ReplayWindow = .{},
early_records: std.ArrayList([]u8) = .empty,

group: u16 = 0,
ecdhe: Ecdhe = .none,
pre_master: [32]u8 = undefined,
master: [48]u8 = undefined,
extended_master_secret: bool = false,
peer_offered_ems: bool = false,
peer_offered_reneg: bool = false,
peer_offered_point_formats: bool = false,
srtp_profile: ?Profile = null,
certificate_requested: bool = false,

peer_cert: ?[]u8 = null,
peer_key: ?Ecdsa.PublicKey = null,
verified: bool = false,

flight: std.ArrayList(FlightItem) = .empty,
retransmit_at: ?u64 = null,
rto: u64 = 0,
retransmits: u32 = 0,
last_resend: u64 = 0,
now: u64 = 0,

out: [1500]u8 = undefined,
out_len: usize = 0,

pub fn init(gpa: std.mem.Allocator, io: std.Io, config: Config, cb: Callbacks) Conn {
    std.debug.assert(config.mtu <= 1500 and config.mtu >= 256);
    return .{
        .gpa = gpa,
        .io = io,
        .config = config,
        .cb = cb,
        .step = if (config.role == .client) .wait_server_hello else .wait_client_hello,
        .rto = config.initial_rto_ms,
    };
}

pub fn deinit(c: *Conn) void {
    c.transcript.deinit(c.gpa);
    c.reasm.deinit(c.gpa);
    c.clearFlight();
    c.flight.deinit(c.gpa);
    for (c.early_records.items) |r| c.gpa.free(r);
    c.early_records.deinit(c.gpa);
    if (c.peer_cert) |p| c.gpa.free(p);
    c.* = undefined;
}

/// Starts the handshake. The client sends its ClientHello; the server just waits.
pub fn start(c: *Conn, now: u64) void {
    if (c.state != .new) return;
    c.now = now;
    c.state = .handshaking;
    if (c.config.role == .client) {
        c.io.random(&c.client_random);
        c.sendClientHello() catch |err| c.fail(err);
    }
}

pub fn isClient(c: *const Conn) bool {
    return c.config.role == .client;
}

/// Sets (or confirms) the fingerprint from the remote SDP; completes the connection if the
/// handshake already finished.
pub fn setRemoteFingerprint(c: *Conn, fp: certs.Fingerprint) void {
    c.config.remote_fingerprint = fp;
    if (c.peer_cert != null) c.checkFingerprint() catch |err| return c.fail(err);
    if (c.step == .done and c.verified and c.state == .handshaking) c.state = .connected;
}

/// RFC 5705 exporter; for DTLS-SRTP use label "EXTRACTOR-dtls_srtp".
pub fn exportKeyingMaterial(c: *const Conn, out: []u8, label: []const u8) !void {
    if (c.state != .connected) return error.NotConnected;
    prf.exporter(out, c.master, label, c.client_random, c.server_random);
}

pub fn sendApplicationData(c: *Conn, data: []const u8) !void {
    if (c.state != .connected) return error.NotConnected;
    if (data.len + record.header_len + record.aead_overhead > c.out.len) return error.MessageTooLong;
    const n = c.write_cipher.?.seal(&c.out, .application_data, 1, c.nextWriteSeq(1), data);
    c.cb.send(c.cb.ctx, c.out[0..n]);
}

/// Sends close_notify and stops.
pub fn close(c: *Conn) void {
    if (c.state == .connected or c.state == .handshaking) c.sendAlert(1, 0);
    c.state = .closed;
    c.retransmit_at = null;
}

pub fn nextTimeout(c: *const Conn) ?u64 {
    return c.retransmit_at;
}

/// Retransmits the last flight when its timer expired (RFC 6347 4.2.4).
pub fn poll(c: *Conn, now: u64) void {
    c.now = now;
    const at = c.retransmit_at orelse return;
    if (now < at or c.state != .handshaking) return;
    c.retransmits += 1;
    if (c.retransmits > c.config.max_retransmits) return c.fail(error.HandshakeTimeout);
    c.rto = @min(c.rto * 2, 8000);
    c.sendFlight();
    c.retransmit_at = now + c.rto;
}

/// Processes one received datagram (already demultiplexed as DTLS).
pub fn handle(c: *Conn, datagram: []const u8, now: u64) void {
    c.now = now;
    if (c.state == .closed or c.state == .failed) return;
    if (c.state == .new) {
        // A server learns of the handshake from the first ClientHello.
        if (c.config.role == .server) c.state = .handshaking else return;
    }
    var peer_resent = false;
    var it: record.Iterator = .{ .data = datagram };
    while (it.next()) |rec| {
        c.handleRecord(rec, &peer_resent) catch |err| return c.fail(err);
        if (c.state == .failed or c.state == .closed) return;
    }
    c.processMessages() catch |err| return c.fail(err);
    // The peer repeated an old flight: ours was lost, so send it again (rate limited).
    if (peer_resent and c.flight.items.len > 0 and now >= c.last_resend + 100) {
        c.last_resend = now;
        c.sendFlight();
    }
}

fn handleRecord(c: *Conn, rec: record.Record, peer_resent: *bool) !void {
    if (rec.version != record.version_dtls12 and rec.version != record.version_dtls10) return;
    var plain_buf: [1500]u8 = undefined;
    var payload: []const u8 = rec.fragment;
    if (rec.epoch == 1) {
        const cipher = c.read_cipher orelse {
            // Keys are not ready yet (reordering); keep a few to replay later.
            if (c.early_records.items.len < 8) {
                var buf = try c.gpa.alloc(u8, record.header_len + rec.fragment.len);
                record.writeHeader(buf[0..record.header_len], rec.content_type, rec.epoch, rec.seq, rec.fragment.len);
                @memcpy(buf[record.header_len..], rec.fragment);
                try c.early_records.append(c.gpa, buf);
            }
            return;
        };
        if (!c.replay.check(rec.seq)) return;
        payload = cipher.open(&plain_buf, rec) catch return; // forged or corrupt: drop silently
        c.replay.accept(rec.seq);
    } else if (rec.epoch != 0) return;

    switch (rec.content_type) {
        .handshake => {
            var rest = payload;
            while (rest.len > 0) {
                const h, const frag = try hs.FragmentHeader.parse(rest);
                rest = rest[hs.header_len + frag.len ..];
                // After the handshake only the peer's retransmissions arrive here.
                if (try c.reasm.add(c.gpa, h, frag) == .old) peer_resent.* = true;
            }
        },
        .change_cipher_spec => {},
        .alert => {
            if (payload.len < 2) return;
            if (payload[1] == 0) {
                c.state = .closed; // close_notify
                c.retransmit_at = null;
            } else if (payload[0] == 2) {
                return error.PeerAlert;
            }
        },
        .application_data => {
            if (rec.epoch == 1 and c.state == .connected) {
                if (c.cb.data) |f| f(c.cb.ctx, payload);
            }
        },
        _ => {},
    }
}

fn processMessages(c: *Conn) !void {
    while (c.reasm.pop(c.gpa)) |m| {
        defer c.gpa.free(m.raw);
        try c.processMessage(m);
        if (c.read_cipher != null and c.early_records.items.len > 0) try c.replayEarlyRecords();
    }
}

fn replayEarlyRecords(c: *Conn) !void {
    var list = c.early_records;
    c.early_records = .empty;
    defer {
        for (list.items) |r| c.gpa.free(r);
        list.deinit(c.gpa);
    }
    var ignored = false;
    for (list.items) |raw| {
        var it: record.Iterator = .{ .data = raw };
        if (it.next()) |rec| try c.handleRecord(rec, &ignored);
    }
}

fn processMessage(c: *Conn, m: hs.Message) !void {
    const body = m.body();
    switch (c.step) {
        // ---- client ----
        .wait_server_hello => switch (m.type) {
            .hello_verify_request => {
                var r = bytes.Reader.init(body);
                _ = try r.int(u16);
                const cookie = try r.vec(1);
                @memcpy(c.cookie[0..cookie.len], cookie);
                c.cookie_len = cookie.len;
                // RFC 6347 4.2.1: the first ClientHello and the HelloVerifyRequest are not hashed.
                c.transcript.clearRetainingCapacity();
                try c.sendClientHello();
            },
            .server_hello => {
                const h = try hs.Hello.parseServer(body);
                if (h.cipher_suite != hs.cipher_ecdhe_ecdsa_aes128_gcm_sha256) return error.UnsupportedCipherSuite;
                if (h.extensions.srtp_profiles.len != 2) return error.NoSrtpProfile;
                const chosen = Profile.fromInt(std.mem.readInt(u16, h.extensions.srtp_profiles[0..2], .big)) orelse return error.NoSrtpProfile;
                if (std.mem.indexOfScalar(Profile, c.config.srtp_profiles, chosen) == null) return error.NoSrtpProfile;
                c.srtp_profile = chosen;
                c.extended_master_secret = h.extensions.extended_master_secret;
                c.server_random = h.random;
                try c.hash(m.raw);
                c.step = .wait_certificate;
            },
            else => return error.UnexpectedMessage,
        },
        .wait_certificate => {
            if (m.type != .certificate) return error.UnexpectedMessage;
            try c.takePeerCertificate(body);
            try c.hash(m.raw);
            c.step = .wait_server_key_exchange;
        },
        .wait_server_key_exchange => {
            if (m.type != .server_key_exchange) return error.UnexpectedMessage;
            try c.clientKeyExchangeFromServer(body);
            try c.hash(m.raw);
            c.step = .wait_certificate_request_or_done;
        },
        .wait_certificate_request_or_done, .wait_server_hello_done => switch (m.type) {
            .certificate_request => {
                if (c.step != .wait_certificate_request_or_done) return error.UnexpectedMessage;
                c.certificate_requested = true;
                try c.hash(m.raw);
                c.step = .wait_server_hello_done;
            },
            .server_hello_done => {
                try c.hash(m.raw);
                try c.sendClientFinishedFlight();
                c.step = .wait_server_finished;
            },
            else => return error.UnexpectedMessage,
        },
        .wait_server_finished => {
            if (m.type != .finished) return error.UnexpectedMessage;
            const want = prf.verifyData(c.master, false, c.transcriptHash());
            if (body.len != 12 or !std.crypto.timing_safe.eql([12]u8, want, body[0..12].*)) return error.BadFinished;
            try c.hash(m.raw);
            c.finish();
        },

        // ---- server ----
        .wait_client_hello => {
            if (m.type != .client_hello) return error.UnexpectedMessage;
            try c.handleClientHello(m, body);
            c.step = .wait_client_certificate;
        },
        .wait_client_certificate => switch (m.type) {
            .certificate => {
                try c.takePeerCertificate(body);
                try c.hash(m.raw);
                c.step = .wait_client_key_exchange;
            },
            // WebRTC requires the client certificate: its fingerprint is the peer's identity.
            else => return error.NoClientCertificate,
        },
        .wait_client_key_exchange => {
            if (m.type != .client_key_exchange) return error.UnexpectedMessage;
            var r = bytes.Reader.init(body);
            try c.deriveShared(try r.vec(1));
            try c.hash(m.raw);
            c.deriveKeys();
            c.step = .wait_certificate_verify;
        },
        .wait_certificate_verify => {
            if (m.type != .certificate_verify) return error.UnexpectedMessage;
            var r = bytes.Reader.init(body);
            if (try r.int(u16) != hs.sig_ecdsa_secp256r1_sha256) return error.UnsupportedSignature;
            const sig = Ecdsa.Signature.fromDer(try r.vec(2)) catch return error.BadSignature;
            sig.verify(c.transcript.items, c.peer_key.?) catch return error.BadSignature;
            try c.hash(m.raw);
            c.step = .wait_client_finished;
        },
        .wait_client_finished => {
            if (m.type != .finished) return error.UnexpectedMessage;
            const want = prf.verifyData(c.master, true, c.transcriptHash());
            if (body.len != 12 or !std.crypto.timing_safe.eql([12]u8, want, body[0..12].*)) return error.BadFinished;
            try c.hash(m.raw);
            try c.sendServerFinishedFlight();
            c.finish();
        },
        .done => {},
    }
}

fn finish(c: *Conn) void {
    c.step = .done;
    c.retransmit_at = null;
    if (c.verified) c.state = .connected;
}

fn fail(c: *Conn, err: anyerror) void {
    if (c.state == .failed) return;
    c.failure = err;
    // handshake_failure (40), or bad_certificate (42) for fingerprint problems.
    const desc: u8 = switch (err) {
        error.FingerprintMismatch, error.BadCertificate, error.UnsupportedCertificate => 42,
        else => 40,
    };
    if (c.state == .handshaking or c.state == .connected) c.sendAlert(2, desc);
    c.state = .failed;
    c.retransmit_at = null;
}

// ---- transcript and keys -------------------------------------------------------------------

fn hash(c: *Conn, raw: []const u8) !void {
    try c.transcript.appendSlice(c.gpa, raw);
}

fn transcriptHash(c: *const Conn) [32]u8 {
    var out: [32]u8 = undefined;
    Sha256.hash(c.transcript.items, &out, .{});
    return out;
}

fn takePeerCertificate(c: *Conn, body: []const u8) !void {
    var r = bytes.Reader.init(body);
    var list = bytes.Reader.init(try r.vec(3));
    const der = list.vec(3) catch return error.NoPeerCertificate;
    c.peer_key = try certs.peerPublicKey(der);
    if (c.peer_cert) |p| c.gpa.free(p);
    c.peer_cert = try c.gpa.dupe(u8, der);
    if (c.config.remote_fingerprint != null) try c.checkFingerprint();
}

fn checkFingerprint(c: *Conn) !void {
    const fp = certs.fingerprintOf(c.peer_cert.?);
    if (!std.mem.eql(u8, &fp, &c.config.remote_fingerprint.?)) return error.FingerprintMismatch;
    c.verified = true;
}

/// Client: verifies the server's signed ECDHE parameters, then computes the shared secret.
fn clientKeyExchangeFromServer(c: *Conn, body: []const u8) !void {
    var r = bytes.Reader.init(body);
    if (try r.int(u8) != 3) return error.UnsupportedCurveType; // named_curve
    const group = try r.int(u16);
    const point = try r.vec(1);
    const params = body[0..r.pos];
    if (try r.int(u16) != hs.sig_ecdsa_secp256r1_sha256) return error.UnsupportedSignature;
    const sig = Ecdsa.Signature.fromDer(try r.vec(2)) catch return error.BadSignature;
    var v = sig.verifier(c.peer_key.?) catch return error.BadSignature;
    v.update(&c.client_random);
    v.update(&c.server_random);
    v.update(params);
    v.verify() catch return error.BadSignature;
    c.group = group;
    c.ecdhe = switch (group) {
        hs.group_secp256r1 => .{ .p256 = Ecdsa.KeyPair.generate(c.io) },
        hs.group_x25519 => .{ .x25519 = X25519.KeyPair.generate(c.io) },
        else => return error.UnsupportedGroup,
    };
    try c.deriveShared(point);
}

fn ourPublicPoint(c: *const Conn, buf: *[65]u8) []const u8 {
    switch (c.ecdhe) {
        .p256 => |kp| {
            buf.* = kp.public_key.toUncompressedSec1();
            return buf[0..65];
        },
        .x25519 => |kp| {
            buf[0..32].* = kp.public_key;
            return buf[0..32];
        },
        .none => unreachable,
    }
}

fn deriveShared(c: *Conn, peer_point: []const u8) !void {
    switch (c.ecdhe) {
        .p256 => |kp| {
            const p = P256.fromSec1(peer_point) catch return error.BadKeyShare;
            const shared = p.mul(kp.secret_key.bytes, .big) catch return error.BadKeyShare;
            c.pre_master = shared.affineCoordinates().x.toBytes(.big);
        },
        .x25519 => |kp| {
            if (peer_point.len != 32) return error.BadKeyShare;
            c.pre_master = X25519.scalarmult(kp.secret_key, peer_point[0..32].*) catch return error.BadKeyShare;
        },
        .none => return error.UnexpectedMessage,
    }
}

/// Master secret and record keys, once the transcript includes ClientKeyExchange.
fn deriveKeys(c: *Conn) void {
    c.master = if (c.extended_master_secret)
        prf.extendedMasterSecret(&c.pre_master, c.transcriptHash())
    else
        prf.masterSecret(&c.pre_master, c.client_random, c.server_random);
    const kb = prf.keyBlock(c.master, c.client_random, c.server_random);
    const client: record.Cipher = .{ .key = kb.client_key, .salt = kb.client_iv };
    const server: record.Cipher = .{ .key = kb.server_key, .salt = kb.server_iv };
    if (c.config.role == .client) {
        c.pending_write_cipher = client;
        c.read_cipher = server;
    } else {
        c.pending_write_cipher = server;
        c.read_cipher = client;
    }
    std.crypto.secureZero(u8, &c.pre_master);
}

// ---- building flights ---------------------------------------------------------------------

fn clearFlight(c: *Conn) void {
    for (c.flight.items) |item| c.gpa.free(item.data);
    c.flight.clearRetainingCapacity();
}

/// Adds a handshake message to the current flight and the transcript.
fn addMessage(c: *Conn, t: hs.Type, body: []const u8, epoch: u16) !void {
    const raw = try hs.wholeMessage(c.gpa, t, c.next_send_seq, body);
    errdefer c.gpa.free(raw);
    c.next_send_seq += 1;
    try c.flight.append(c.gpa, .{ .content_type = .handshake, .epoch = epoch, .data = raw });
    try c.hash(raw);
}

fn addChangeCipherSpec(c: *Conn) !void {
    const data = try c.gpa.dupe(u8, &.{1});
    try c.flight.append(c.gpa, .{ .content_type = .change_cipher_spec, .epoch = 0, .data = data });
    c.write_cipher = c.pending_write_cipher;
    c.write_epoch = 1;
}

fn addFinished(c: *Conn) !void {
    const vd = prf.verifyData(c.master, c.config.role == .client, c.transcriptHash());
    try c.addMessage(.finished, &vd, 1);
}

fn armTimer(c: *Conn) void {
    c.rto = c.config.initial_rto_ms;
    c.retransmits = 0;
    c.retransmit_at = c.now + c.rto;
}

fn sendClientHello(c: *Conn) !void {
    c.clearFlight();
    var w = bytes.Writer.init(c.gpa);
    defer w.deinit();
    try w.int(u16, record.version_dtls12);
    try w.put(&c.client_random);
    try w.vec(1, ""); // session id
    try w.vec(1, c.cookie[0..c.cookie_len]);
    try w.begin(2);
    try w.int(u16, hs.cipher_ecdhe_ecdsa_aes128_gcm_sha256);
    w.end();
    try w.vec(1, &.{0}); // null compression
    try w.begin(2); // extensions
    {
        try w.int(u16, hs.ext.supported_groups);
        try w.begin(2);
        try w.begin(2);
        try w.int(u16, hs.group_secp256r1);
        try w.int(u16, hs.group_x25519);
        w.end();
        w.end();

        try w.int(u16, hs.ext.ec_point_formats);
        try w.begin(2);
        try w.vec(1, &.{0}); // uncompressed
        w.end();

        try w.int(u16, hs.ext.signature_algorithms);
        try w.begin(2);
        try w.begin(2);
        try w.int(u16, hs.sig_ecdsa_secp256r1_sha256);
        w.end();
        w.end();

        try w.int(u16, hs.ext.use_srtp);
        try w.begin(2);
        try w.begin(2);
        for (c.config.srtp_profiles) |p| try w.int(u16, @backingInt(p));
        w.end();
        try w.vec(1, ""); // no MKI
        w.end();

        try w.int(u16, hs.ext.extended_master_secret);
        try w.vec(2, "");

        try w.int(u16, hs.ext.renegotiation_info);
        try w.begin(2);
        try w.vec(1, "");
        w.end();
    }
    w.end();
    try c.addMessage(.client_hello, w.written(), 0);
    c.sendFlight();
    c.armTimer();
}

fn handleClientHello(c: *Conn, m: hs.Message, body: []const u8) !void {
    const h = try hs.Hello.parseClient(body);
    if (!h.offersSuite(hs.cipher_ecdhe_ecdsa_aes128_gcm_sha256)) return error.UnsupportedCipherSuite;
    // Pick our most preferred SRTP profile that the client offers.
    for (c.config.srtp_profiles) |p| {
        if (hs.listHas(h.extensions.srtp_profiles, @backingInt(p))) {
            c.srtp_profile = p;
            break;
        }
    } else return error.NoSrtpProfile;
    const groups = h.extensions.groups;
    c.group = if (groups.len == 0 or hs.listHas(groups, hs.group_secp256r1))
        hs.group_secp256r1
    else if (hs.listHas(groups, hs.group_x25519))
        hs.group_x25519
    else
        return error.UnsupportedGroup;
    c.ecdhe = if (c.group == hs.group_secp256r1) .{ .p256 = Ecdsa.KeyPair.generate(c.io) } else .{ .x25519 = X25519.KeyPair.generate(c.io) };
    c.client_random = h.random;
    c.io.random(&c.server_random);
    c.extended_master_secret = h.extensions.extended_master_secret;
    c.peer_offered_reneg = h.extensions.renegotiation_info or h.offersSuite(0x00FF);
    c.peer_offered_point_formats = h.extensions.point_formats;
    // A ClientHello carries message_seq 0 or 1 (after a cookie exchange elsewhere); we answer
    // with the same numbering so the peer's expectations hold.
    c.next_send_seq = m.seq;
    try c.hash(m.raw);

    c.clearFlight();
    var w = bytes.Writer.init(c.gpa);
    defer w.deinit();

    // ServerHello
    try w.int(u16, record.version_dtls12);
    try w.put(&c.server_random);
    try w.vec(1, "");
    try w.int(u16, hs.cipher_ecdhe_ecdsa_aes128_gcm_sha256);
    try w.int(u8, 0);
    try w.begin(2);
    {
        try w.int(u16, hs.ext.use_srtp);
        try w.begin(2);
        try w.begin(2);
        try w.int(u16, @backingInt(c.srtp_profile.?));
        w.end();
        try w.vec(1, "");
        w.end();
        if (c.extended_master_secret) {
            try w.int(u16, hs.ext.extended_master_secret);
            try w.vec(2, "");
        }
        if (c.peer_offered_reneg) {
            try w.int(u16, hs.ext.renegotiation_info);
            try w.begin(2);
            try w.vec(1, "");
            w.end();
        }
        if (c.peer_offered_point_formats) {
            try w.int(u16, hs.ext.ec_point_formats);
            try w.begin(2);
            try w.vec(1, &.{0});
            w.end();
        }
    }
    w.end();
    try c.addMessage(.server_hello, w.written(), 0);

    // Certificate
    w.list.clearRetainingCapacity();
    try c.writeCertificate(&w);
    try c.addMessage(.certificate, w.written(), 0);

    // ServerKeyExchange: named curve + our point, signed with client_random + server_random.
    w.list.clearRetainingCapacity();
    try w.int(u8, 3);
    try w.int(u16, c.group);
    var point_buf: [65]u8 = undefined;
    try w.vec(1, c.ourPublicPoint(&point_buf));
    const params_len = w.written().len;
    var signer = try c.config.certificate.key.signer(null);
    signer.update(&c.client_random);
    signer.update(&c.server_random);
    signer.update(w.written()[0..params_len]);
    const sig = try signer.finalize();
    var sig_buf: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
    try w.int(u16, hs.sig_ecdsa_secp256r1_sha256);
    try w.vec(2, sig.toDer(&sig_buf));
    try c.addMessage(.server_key_exchange, w.written(), 0);

    // CertificateRequest: ecdsa_sign, ecdsa_secp256r1_sha256, no CA names.
    w.list.clearRetainingCapacity();
    try w.vec(1, &.{64});
    try w.begin(2);
    try w.int(u16, hs.sig_ecdsa_secp256r1_sha256);
    w.end();
    try w.vec(2, "");
    try c.addMessage(.certificate_request, w.written(), 0);

    try c.addMessage(.server_hello_done, "", 0);
    c.sendFlight();
    c.armTimer();
}

fn writeCertificate(c: *Conn, w: *bytes.Writer) !void {
    try w.begin(3);
    try w.vec(3, c.config.certificate.der);
    w.end();
}

fn sendClientFinishedFlight(c: *Conn) !void {
    c.clearFlight();
    var w = bytes.Writer.init(c.gpa);
    defer w.deinit();
    if (c.certificate_requested) {
        try c.writeCertificate(&w);
        try c.addMessage(.certificate, w.written(), 0);
    }
    w.list.clearRetainingCapacity();
    var point_buf: [65]u8 = undefined;
    try w.vec(1, c.ourPublicPoint(&point_buf));
    try c.addMessage(.client_key_exchange, w.written(), 0);
    c.deriveKeys();
    if (c.certificate_requested) {
        const sig = try c.config.certificate.key.sign(c.transcript.items, null);
        var sig_buf: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
        w.list.clearRetainingCapacity();
        try w.int(u16, hs.sig_ecdsa_secp256r1_sha256);
        try w.vec(2, sig.toDer(&sig_buf));
        try c.addMessage(.certificate_verify, w.written(), 0);
    }
    try c.addChangeCipherSpec();
    try c.addFinished();
    c.sendFlight();
    c.armTimer();
}

fn sendServerFinishedFlight(c: *Conn) !void {
    c.clearFlight();
    try c.addChangeCipherSpec();
    try c.addFinished();
    c.sendFlight();
    // The last flight has no timer: the client's retransmission tells us it was lost.
}

// ---- sending ------------------------------------------------------------------------------

fn nextWriteSeq(c: *Conn, epoch: u16) u64 {
    defer c.write_seq[epoch] += 1;
    return c.write_seq[epoch];
}

/// Sends (or resends) the current flight, fragmenting messages and packing records into
/// datagrams of at most `mtu` bytes. Each transmission uses fresh record sequence numbers.
fn sendFlight(c: *Conn) void {
    c.out_len = 0;
    for (c.flight.items) |item| {
        const overhead: usize = record.header_len + @as(usize, if (item.epoch == 1) record.aead_overhead else 0);
        if (item.content_type != .handshake) {
            c.emitRecord(item.content_type, item.epoch, item.data, overhead);
            continue;
        }
        const h0, const body = hs.FragmentHeader.parse(item.data) catch unreachable;
        const max_frag = c.config.mtu - overhead - hs.header_len;
        var off: usize = 0;
        while (true) {
            const n = @min(max_frag, body.len - off);
            var frag: [1500]u8 = undefined;
            var h = h0;
            h.offset = @intCast(off);
            h.frag_len = @intCast(n);
            h.write(frag[0..hs.header_len]);
            @memcpy(frag[hs.header_len..][0..n], body[off..][0..n]);
            c.emitRecord(.handshake, item.epoch, frag[0 .. hs.header_len + n], overhead);
            off += n;
            if (off >= body.len) break;
        }
    }
    c.flushOut();
}

fn emitRecord(c: *Conn, ct: record.ContentType, epoch: u16, payload: []const u8, overhead: usize) void {
    if (c.out_len + overhead + payload.len > c.config.mtu) c.flushOut();
    const dst = c.out[c.out_len..];
    if (epoch == 0) {
        record.writeHeader(dst[0..record.header_len], ct, 0, c.nextWriteSeq(0), payload.len);
        @memcpy(dst[record.header_len..][0..payload.len], payload);
        c.out_len += record.header_len + payload.len;
    } else {
        c.out_len += c.write_cipher.?.seal(dst, ct, 1, c.nextWriteSeq(1), payload);
    }
}

fn flushOut(c: *Conn) void {
    if (c.out_len == 0) return;
    c.cb.send(c.cb.ctx, c.out[0..c.out_len]);
    c.out_len = 0;
}

fn sendAlert(c: *Conn, level: u8, desc: u8) void {
    var buf: [64]u8 = undefined;
    const payload = [2]u8{ level, desc };
    if (c.write_cipher) |cipher| {
        const n = cipher.seal(&buf, .alert, 1, c.nextWriteSeq(1), &payload);
        c.cb.send(c.cb.ctx, buf[0..n]);
    } else {
        record.writeHeader(buf[0..record.header_len], .alert, 0, c.nextWriteSeq(0), 2);
        buf[record.header_len..][0..2].* = payload;
        c.cb.send(c.cb.ctx, buf[0 .. record.header_len + 2]);
    }
}

// ---- tests --------------------------------------------------------------------------------

const testing = std.testing;

/// Two connections wired back to back through queues, with optional loss.
const Pipe = struct {
    gpa: std.mem.Allocator,
    queue: std.ArrayList([]u8) = .empty,
    drop_every: usize = 0,
    count: usize = 0,
    app: std.ArrayList(u8) = .empty,

    fn send(ctx: *anyopaque, d: []const u8) void {
        const p: *Pipe = @ptrCast(@alignCast(ctx));
        p.count += 1;
        // Pseudo-random loss of about 1 in drop_every datagrams.
        const r = (p.count *% 2654435761) >> 7;
        if (p.drop_every != 0 and r % p.drop_every == 0) return;
        p.queue.append(p.gpa, p.gpa.dupe(u8, d) catch unreachable) catch unreachable;
    }

    fn data(ctx: *anyopaque, d: []const u8) void {
        const p: *Pipe = @ptrCast(@alignCast(ctx));
        p.app.appendSlice(p.gpa, d) catch unreachable;
    }

    fn deinit(p: *Pipe) void {
        for (p.queue.items) |d| p.gpa.free(d);
        p.queue.deinit(p.gpa);
        p.app.deinit(p.gpa);
    }

    fn deliver(p: *Pipe, to: *Conn, now: u64) void {
        const items = p.queue.toOwnedSlice(p.gpa) catch unreachable;
        defer p.gpa.free(items);
        for (items) |d| {
            to.handle(d, now);
            p.gpa.free(d);
        }
    }
};

fn runPair(drop_every: usize, mtu: usize) !void {
    const gpa = testing.allocator;
    var ca = try certs.Certificate.generate(gpa, testing.io, 30);
    defer ca.deinit(gpa);
    var cb_ = try certs.Certificate.generate(gpa, testing.io, 30);
    defer cb_.deinit(gpa);

    var to_server: Pipe = .{ .gpa = gpa, .drop_every = drop_every };
    defer to_server.deinit();
    var to_client: Pipe = .{ .gpa = gpa, .drop_every = drop_every };
    defer to_client.deinit();

    var client = Conn.init(gpa, testing.io, .{ .role = .client, .certificate = &ca, .remote_fingerprint = cb_.fingerprint, .mtu = mtu }, .{ .ctx = &to_server, .send = Pipe.send, .data = Pipe.data });
    defer client.deinit();
    var server = Conn.init(gpa, testing.io, .{ .role = .server, .certificate = &cb_, .remote_fingerprint = ca.fingerprint, .mtu = mtu }, .{ .ctx = &to_client, .send = Pipe.send, .data = Pipe.data });
    defer server.deinit();

    var now: u64 = 1000;
    client.start(now);
    server.start(now);
    var rounds: usize = 0;
    while (rounds < 200 and (client.state != .connected or server.state != .connected)) : (rounds += 1) {
        to_server.deliver(&server, now);
        to_client.deliver(&client, now);
        now += 100;
        client.poll(now);
        server.poll(now);
    }
    if (client.state != .connected or server.state != .connected) {
        std.debug.print("client {t} {?} {t} / server {t} {?} {t}\n", .{ client.state, client.failure, client.step, server.state, server.failure, server.step });
    }
    try testing.expectEqual(State.connected, client.state);
    try testing.expectEqual(State.connected, server.state);
    try testing.expectEqual(client.srtp_profile.?, server.srtp_profile.?);

    var k1: [56]u8 = undefined;
    var k2: [56]u8 = undefined;
    try client.exportKeyingMaterial(&k1, "EXTRACTOR-dtls_srtp");
    try server.exportKeyingMaterial(&k2, "EXTRACTOR-dtls_srtp");
    try testing.expectEqualSlices(u8, &k1, &k2);

    // Application data (resent until the lossy pipe lets it through). The server reports
    // received data through its own callback context, which is to_client.
    var tries: usize = 0;
    while (to_client.app.items.len == 0 and tries < 10) : (tries += 1) {
        try client.sendApplicationData("ping");
        to_server.deliver(&server, now);
    }
    try testing.expectEqualStrings("ping", to_client.app.items[0..4]);
}

test "DTLS handshake client <-> server, P-256, mutual fingerprints" {
    try runPair(0, 1200);
}

test "DTLS handshake survives loss and small MTU fragmentation" {
    try runPair(3, 300);
    try runPair(2, 1200);
}

test "DTLS rejects a wrong fingerprint" {
    const gpa = testing.allocator;
    var ca = try certs.Certificate.generate(gpa, testing.io, 30);
    defer ca.deinit(gpa);
    var cb_ = try certs.Certificate.generate(gpa, testing.io, 30);
    defer cb_.deinit(gpa);
    var to_server: Pipe = .{ .gpa = gpa };
    defer to_server.deinit();
    var to_client: Pipe = .{ .gpa = gpa };
    defer to_client.deinit();
    var client = Conn.init(gpa, testing.io, .{ .role = .client, .certificate = &ca, .remote_fingerprint = ca.fingerprint }, .{ .ctx = &to_server, .send = Pipe.send });
    defer client.deinit();
    var server = Conn.init(gpa, testing.io, .{ .role = .server, .certificate = &cb_, .remote_fingerprint = ca.fingerprint }, .{ .ctx = &to_client, .send = Pipe.send });
    defer server.deinit();
    client.start(0);
    for (0..5) |_| {
        to_server.deliver(&server, 0);
        to_client.deliver(&client, 0);
    }
    try testing.expectEqual(State.failed, client.state);
    try testing.expectEqual(@as(?anyerror, error.FingerprintMismatch), client.failure);
}
