//! PeerConnection: offer/answer, ICE candidates, DTLS-SRTP and one audio (Opus) and one video
//! (H.264) track in each direction, interoperable with a browser RTCPeerConnection using
//! bundlePolicy max-bundle and rtcp-mux (the browser defaults).
//!
//! Sans-IO: the app passes received datagrams to `receive`, calls `poll` when `nextTimeout`
//! is due, and gets everything else (local candidates, states, received frames, keyframe
//! requests) through `Handler`. Codecs live in the app: encoded Opus packets and H.264
//! access units (Annex-B) go in with `sendAudio` / `sendVideo` and come out as events.

const std = @import("std");

const net = @import("net.zig");
const IceAgent = @import("ice/Agent.zig");
const candidate = @import("ice/candidate.zig");
const PeerTransport = @import("transport/PeerTransport.zig");
const DtlsConn = @import("dtls/Conn.zig");
const certs = @import("dtls/cert.zig");
const srtp = @import("media/srtp.zig");
const rtp = @import("media/rtp.zig");
const rtcp = @import("media/rtcp.zig");
const h264 = @import("media/h264.zig");
const opus = @import("media/opus.zig");
const JitterBuffer = @import("media/JitterBuffer.zig");
const BitrateController = @import("media/BitrateController.zig");
const sdp = @import("sdp/sdp.zig");

pub const Kind = enum { audio, video };

pub const ConnectionState = PeerTransport.State;
pub const IceState = IceAgent.State;

pub const Event = union(enum) {
    /// "candidate:..." to send to the peer (RTCIceCandidateInit.candidate, sdpMid "0").
    local_candidate: []const u8,
    gathering_done,
    ice_state: IceState,
    connection_state: ConnectionState,
    /// One received Opus packet.
    audio_frame: struct { ssrc: u32, timestamp: u32, data: []const u8 },
    /// One received H.264 access unit in Annex-B form.
    /// `rotation`: degrees clockwise the picture must be turned to stand upright (0, 90, 180
    /// or 270), from the sender's video-orientation extension.
    video_frame: struct { ssrc: u32, timestamp: u32, data: []const u8, keyframe: bool, corrupt: bool, rotation: u16 = 0 },
    /// The peer asked for a keyframe (PLI/FIR): the app should make its encoder emit an IDR.
    keyframe_requested,
    /// The peer's receive-side bandwidth estimate for our video (REMB), bits per second.
    remote_bitrate: u64,
    /// The bitrate our video encoder should use now (REMB, loss and RTT combined), with the
    /// loss and round-trip time behind it. Sent when it changes by 5 % or more.
    send_bitrate: struct { bps: u32, loss: f32, rtt_ms: u32 },
};

pub const Handler = struct {
    ctx: *anyopaque,
    onEvent: *const fn (ctx: *anyopaque, event: Event) void,
};

pub const Config = struct {
    /// UDP sockets the app opened; each yields a host candidate.
    sockets: []const net.Socket,
    /// Resolved STUN/TURN servers (see `driver.resolveIceServers`).
    servers: []const IceAgent.Server = &.{},
    /// iceTransportPolicy "relay": only TURN candidates.
    ice_relay_only: bool = false,
    audio: bool = true,
    video: bool = true,
    /// Reuse a certificate across calls (its fingerprint is the identity); generated if null.
    certificate: ?*const certs.Certificate = null,
    srtp_profiles: []const srtp.Profile = &.{ .aead_aes128_gcm, .aes128_cm_sha1_80 },
    /// Advertised to the sender with REMB.
    max_video_bitrate: u64 = 2_500_000,
    /// Our video's send bitrate range (see `Event.send_bitrate`).
    send_bitrate: BitrateController.Config = .{},
    audio_jitter_ms: u64 = 80,
    video_jitter_ms: u64 = 250,
    handler: Handler,
};

pub const SdpType = enum { offer, answer };

const opus_pt_default = 111;
const h264_pt_default = 102;
/// RTP header extension for the picture's rotation (3GPP TS 26.114, "CVO").
const cvo_uri = "urn:3gpp:video-orientation";
const cvo_default_id = 13;
/// Send time on every video packet: what the receiver's REMB estimator needs.
const abs_send_time_uri = "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time";
const abs_send_time_default_id = 2;
const h264_fmtp = "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f";
const video_feedback = [_][]const u8{ "goog-remb", "ccm fir", "nack", "nack pli" };
const max_rtp_payload = 1200 - 12 - 16; // datagram budget minus RTP header and SRTP tag
const history_len = 512;

const Track = struct {
    kind: Kind,
    mid: [32]u8 = undefined,
    mid_len: usize = 0,
    accepted: bool = false,
    send: bool = false,
    recv: bool = false,
    pt: u8,
    local_ssrc: u32,
    seq: u16,
    timestamp: u32,
    packets: u32 = 0,
    octets: u32 = 0,
    last_rtp_ts: u32 = 0,
    last_send_ms: u64 = 0,
    sent_any: bool = false,
    remote_nack: bool = false,
    /// Negotiated id of the video-orientation extension (0: not negotiated).
    cvo_id: u8 = 0,
    abs_id: u8 = 0,

    fn midText(t: *const Track) []const u8 {
        return t.mid[0..t.mid_len];
    }

    fn setMid(t: *Track, m: []const u8) void {
        const n = @min(m.len, t.mid.len);
        @memcpy(t.mid[0..n], m[0..n]);
        t.mid_len = n;
    }
};

const RemoteStream = struct {
    rotation: u16 = 0,
    ssrc: u32,
    kind: Kind,
    clock: u32,
    jitter: JitterBuffer,
    base_seq: ?u64 = null,
    max_seq: u64 = 0,
    received: u64 = 0,
    expected_prior: u64 = 0,
    received_prior: u64 = 0,
    transit: ?i64 = null,
    jitter_q4: u32 = 0,
    last_sr_mid: u32 = 0,
    last_sr_at: u64 = 0,
    last_nack_at: u64 = 0,
    last_pli_at: u64 = 0,
    frames: u64 = 0,
    bytes: u64 = 0,
};

const Sent = struct { seq: u16, len: u16, data: [1300]u8 };

const max_mlines = 8;

fn SmallText(comptime n: usize) type {
    return struct {
        buf: [n]u8 = undefined,
        len: usize = 0,

        fn set(t: *@This(), s: []const u8) void {
            t.len = @min(s.len, n);
            @memcpy(t.buf[0..t.len], s[0..t.len]);
        }

        fn text(t: *const @This()) []const u8 {
            return t.buf[0..t.len];
        }
    };
}

/// One m-line of the negotiated session: one of our tracks, or a rejected section we
/// echo back with port 0 (so answers mirror offers line for line).
const MLine = struct {
    track: ?u1,
    kind: SmallText(16) = .{},
    mid: SmallText(32) = .{},
    proto: SmallText(48) = .{},
    formats: SmallText(96) = .{},
};

pub const Stats = struct {
    ice: IceState,
    connection: ConnectionState,
    srtp_profile: ?srtp.Profile,
    local_candidate: ?candidate.Candidate,
    remote_candidate: ?candidate.Candidate,
    audio_sent: u32,
    video_sent: u32,
    audio_received: u64,
    video_received: u64,
    audio_frames: u64,
    video_frames: u64,
    srtp_errors: u64,
    remote_bitrate: u64,
};

pub const PeerConnection = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    config: Config,
    owned_cert: ?certs.Certificate = null,
    cert: *const certs.Certificate,
    transport: PeerTransport,

    signaling: enum { stable, have_local_offer, have_remote_offer } = .stable,
    offerer: bool = false,
    session_id: u64,
    session_version: u32 = 2,
    cname: [16]u8,
    mlines: [max_mlines]MLine = undefined,
    mline_count: usize = 0,
    answered_once: bool = false,
    tracks: [2]Track,
    local_candidates: std.ArrayList([]u8) = .empty,
    gathering_done: bool = false,

    srtp_send: ?srtp.Context = null,
    srtp_recv: ?srtp.Context = null,
    srtp_errors: u64 = 0,
    streams: std.ArrayList(RemoteStream) = .empty,
    remote_ssrcs: [2]std.ArrayList(u32) = .{ .empty, .empty },
    history: []Sent,
    history_next: usize = 0,
    depacketizer: h264.Depacketizer = .{},
    next_rtcp_at: u64 = 0,
    remote_bitrate: u64 = 0,
    now: u64 = 0,
    /// Rotation sent with our video (video-orientation extension), degrees clockwise.
    video_rotation: u16 = 0,
    /// `restartIce` was called: the next offer carries new ICE credentials.
    restart_pending: bool = false,
    bitrate: BitrateController = undefined,
    emitted_bitrate: u32 = 0,
    /// Tests only: drop this percentage of our outgoing video packets (to see adaptation).
    debug_drop_video_percent: u8 = 0,
    drop_counter: u32 = 0,
    /// Video packets sent and NACKed since the last report: retransmissions hide loss from
    /// receiver reports, NACKs do not.
    sent_window: u32 = 0,
    nacked_window: u32 = 0,

    pub fn create(gpa: std.mem.Allocator, io: std.Io, config: Config) !*PeerConnection {
        const pc = try gpa.create(PeerConnection);
        errdefer gpa.destroy(pc);
        var rnd: [24]u8 = undefined;
        io.random(&rnd);
        pc.* = .{
            .gpa = gpa,
            .io = io,
            .config = config,
            .cert = undefined,
            .transport = undefined,
            .session_id = std.mem.readInt(u64, rnd[0..8], .little) >> 2,
            .cname = undefined,
            .tracks = .{
                .{ .kind = .audio, .pt = opus_pt_default, .local_ssrc = std.mem.readInt(u32, rnd[8..12], .little) | 1, .seq = std.mem.readInt(u16, rnd[16..18], .little) & 0x7fff, .timestamp = std.mem.readInt(u32, rnd[18..22], .little) },
                .{ .kind = .video, .pt = h264_pt_default, .local_ssrc = std.mem.readInt(u32, rnd[12..16], .little) | 1, .seq = std.mem.readInt(u16, rnd[22..24], .little) & 0x7fff, .timestamp = std.mem.readInt(u32, rnd[18..22], .little) ^ 0x5a5a5a5a },
            },
            .history = try gpa.alloc(Sent, history_len),
        };
        errdefer gpa.free(pc.history);
        for (pc.history) |*h| h.len = 0;
        pc.bitrate = .init(config.send_bitrate);
        const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        io.random(&pc.cname);
        for (&pc.cname) |*c| c.* = alphabet[c.* % alphabet.len];
        if (config.certificate) |c| {
            pc.cert = c;
        } else {
            pc.owned_cert = try certs.Certificate.generate(gpa, io, 30);
            pc.cert = &pc.owned_cert.?;
        }
        errdefer if (pc.owned_cert) |*c| c.deinit(gpa);
        try pc.transport.init(gpa, io, .{
            .ice = .{ .role = .controlling, .servers = config.servers, .relay_only = config.ice_relay_only },
            .certificate = pc.cert,
            .srtp_profiles = config.srtp_profiles,
        }, config.sockets, .{
            .ctx = pc,
            .candidate = onCandidate,
            .gathering_done = onGatheringDone,
            .ice_state = onIceState,
            .secure = onSecure,
            .state = onState,
            .media = onMedia,
        });
        return pc;
    }

    pub fn destroy(pc: *PeerConnection) void {
        const gpa = pc.gpa;
        pc.transport.deinit();
        for (pc.local_candidates.items) |c| gpa.free(c);
        pc.local_candidates.deinit(gpa);
        for (pc.streams.items) |*s| s.jitter.deinit();
        pc.streams.deinit(gpa);
        for (&pc.remote_ssrcs) |*l| l.deinit(gpa);
        pc.depacketizer.deinit(gpa);
        gpa.free(pc.history);
        if (pc.owned_cert) |*c| c.deinit(gpa);
        gpa.destroy(pc);
    }

    fn emit(pc: *PeerConnection, e: Event) void {
        pc.config.handler.onEvent(pc.config.handler.ctx, e);
    }

    pub fn fingerprint(pc: *const PeerConnection) certs.Fingerprint {
        return pc.cert.fingerprint;
    }

    // ---- transport callbacks -------------------------------------------------------------

    fn onCandidate(ctx: *anyopaque, c: *const IceAgent.Candidate) void {
        const pc: *PeerConnection = @ptrCast(@alignCast(ctx));
        var buf: [256]u8 = undefined;
        const line = std.fmt.bufPrint(&buf, "{f}", .{c.*}) catch return;
        const copy = pc.gpa.dupe(u8, line) catch return;
        pc.local_candidates.append(pc.gpa, copy) catch {
            pc.gpa.free(copy);
            return;
        };
        pc.emit(.{ .local_candidate = copy });
    }

    fn onGatheringDone(ctx: *anyopaque) void {
        const pc: *PeerConnection = @ptrCast(@alignCast(ctx));
        pc.gathering_done = true;
        pc.emit(.gathering_done);
    }

    fn onIceState(ctx: *anyopaque, s: IceAgent.State) void {
        const pc: *PeerConnection = @ptrCast(@alignCast(ctx));
        pc.emit(.{ .ice_state = s });
    }

    fn onState(ctx: *anyopaque, s: PeerTransport.State) void {
        const pc: *PeerConnection = @ptrCast(@alignCast(ctx));
        pc.emit(.{ .connection_state = s });
    }

    fn onSecure(ctx: *anyopaque) void {
        const pc: *PeerConnection = @ptrCast(@alignCast(ctx));
        const profile = pc.transport.srtpProfile() orelse return;
        var material: [64]u8 = undefined;
        const m = material[0..profile.keyingMaterialLen()];
        pc.transport.exportSrtpKeys(m) catch return;
        const ctxs = srtp.Context.fromKeyingMaterial(profile, m, pc.transport.isDtlsClient());
        pc.srtp_send = ctxs.send;
        pc.srtp_recv = ctxs.recv;
        std.crypto.secureZero(u8, &material);
        pc.next_rtcp_at = pc.now + 500;
        pc.emitBitrate(true);
    }

    fn dropForTest(pc: *PeerConnection) bool {
        if (pc.debug_drop_video_percent == 0) return false;
        pc.drop_counter +%= 1;
        return ((pc.drop_counter *% 2654435761) >> 8) % 100 < pc.debug_drop_video_percent;
    }

    fn emitBitrate(pc: *PeerConnection, force: bool) void {
        const bps = pc.bitrate.current(pc.now);
        const last: u64 = pc.emitted_bitrate;
        if (!force and last != 0 and @as(u64, bps) * 20 > last * 19 and @as(u64, bps) * 20 < last * 21) return;
        pc.emitted_bitrate = bps;
        pc.emit(.{ .send_bitrate = .{ .bps = bps, .loss = pc.bitrate.loss, .rtt_ms = pc.bitrate.rtt_ms orelse 0 } });
    }

    /// Report blocks about our video (in SR or RR): loss and RTT into the bitrate controller.
    fn onReportBlocks(pc: *PeerConnection, p: rtcp.Packet) void {
        var i: usize = 0;
        while (p.reportBlock(i)) |blk| : (i += 1) {
            if (blk.ssrc != pc.tracks[1].local_ssrc) continue;
            var rtt: ?u32 = null;
            if (blk.last_sr != 0) {
                const unix_ms: u64 = @intCast(@divTrunc(std.Io.Timestamp.now(pc.io, .real).nanoseconds, std.time.ns_per_ms));
                const now_mid: u32 = @truncate(rtcp.ntpFromUnixMs(unix_ms) >> 16);
                const units = now_mid -% blk.last_sr -% blk.delay_since_last_sr;
                if (units < 65536 * 10) rtt = @intCast(@as(u64, units) * 1000 / 65536);
            }
            var fraction: u8 = blk.fraction_lost;
            if (pc.sent_window >= 20) {
                const nacked: u8 = @intCast(@min(255, @as(u64, pc.nacked_window) * 256 / pc.sent_window));
                fraction = @max(fraction, nacked);
            }
            pc.sent_window = 0;
            pc.nacked_window = 0;
            pc.bitrate.onReport(pc.now, fraction, rtt);
            pc.emitBitrate(false);
        }
    }

    // ---- offer / answer ------------------------------------------------------------------

    /// Creates an offer (audio and/or video, sendrecv), applies it as the local description
    /// and starts gathering. Returns SDP text owned by `gpa`.
    pub fn createOffer(pc: *PeerConnection, gpa: std.mem.Allocator, now: u64) ![]u8 {
        pc.now = now;
        if (pc.signaling != .stable) return error.InvalidState;
        const first = pc.mline_count == 0;
        if (first) {
            // Initial offer: we control ICE; one m-line per enabled kind.
            pc.offerer = true;
            pc.transport.ice.setRole(.controlling);
            var mid: u8 = 0;
            for (&pc.tracks, 0..) |*t, i| {
                t.accepted = if (t.kind == .audio) pc.config.audio else pc.config.video;
                if (!t.accepted) continue;
                t.send = true;
                t.recv = true;
                var b: [4]u8 = undefined;
                t.setMid(std.fmt.bufPrint(&b, "{d}", .{mid}) catch unreachable);
                mid += 1;
                pc.mlines[pc.mline_count] = .{ .track = @intCast(i) };
                pc.mline_count += 1;
            }
            pc.tracks[1].cvo_id = cvo_default_id;
            pc.tracks[1].abs_id = abs_send_time_default_id;
        } else {
            // Re-offer: same m-lines and mids; ICE and DTLS roles stay as negotiated. A kind
            // missing from the session (a call that began as voice) gets its m-line now, as a
            // browser's addTrack would.
            pc.session_version += 1;
            for (&pc.tracks, 0..) |*t, i| {
                const enabled = if (t.kind == .audio) pc.config.audio else pc.config.video;
                if (!t.accepted and enabled) pc.addTrackLine(@intCast(i));
                if (t.accepted) {
                    t.send = true;
                    t.recv = true;
                }
            }
        }
        if (pc.restart_pending) {
            pc.restart_pending = false;
            pc.restartIceNow();
        }
        pc.signaling = .have_local_offer;
        try pc.transport.ice.gather(now);
        return pc.localDescription(gpa);
    }

    /// Creates the answer to the remote offer set with `setRemoteDescription`.
    pub fn createAnswer(pc: *PeerConnection, gpa: std.mem.Allocator, now: u64) ![]u8 {
        pc.now = now;
        if (pc.signaling != .have_remote_offer) return error.InvalidState;
        pc.signaling = .stable;
        if (pc.answered_once) pc.session_version += 1;
        pc.answered_once = true;
        try pc.transport.ice.gather(now);
        pc.transport.setDtlsRole(.client); // first answer: setup:active (no-op afterwards)
        return pc.localDescription(gpa);
    }

    /// The current local description, including candidates gathered so far.
    pub fn localDescription(pc: *PeerConnection, gpa: std.mem.Allocator) ![]u8 {
        var media: [max_mlines]sdp.LocalMedia = undefined;
        var n: usize = 0;
        var fp_buf: [95]u8 = undefined;
        const audio_codec = [_]sdp.LocalCodec{.{ .pt = pc.tracks[0].pt, .name = "opus", .clock = opus.clock_rate, .channels = 2, .fmtp = opus.default_fmtp }};
        var video_ext: [2]sdp.Extmap = undefined;
        var video_ext_n: usize = 0;
        if (pc.tracks[1].abs_id != 0) {
            video_ext[video_ext_n] = .{ .id = pc.tracks[1].abs_id, .uri = abs_send_time_uri };
            video_ext_n += 1;
        }
        if (pc.tracks[1].cvo_id != 0) {
            video_ext[video_ext_n] = .{ .id = pc.tracks[1].cvo_id, .uri = cvo_uri };
            video_ext_n += 1;
        }
        const video_codec = [_]sdp.LocalCodec{.{ .pt = pc.tracks[1].pt, .name = "H264", .clock = 90000, .fmtp = h264_fmtp, .feedback = &video_feedback }};
        // m-lines in negotiated order (an answer mirrors the offer, rejected lines included).
        for (pc.mlines[0..pc.mline_count]) |*ml| {
            const i = ml.track orelse {
                media[n] = .{
                    .kind = ml.kind.text(),
                    .mid = ml.mid.text(),
                    .codecs = &.{},
                    .rejected = true,
                    .raw_proto = ml.proto.text(),
                    .raw_formats = ml.formats.text(),
                };
                n += 1;
                continue;
            };
            const t = &pc.tracks[i];
            const dir: sdp.Direction = if (t.send and t.recv) .sendrecv else if (t.send) .sendonly else if (t.recv) .recvonly else .inactive;
            media[n] = .{
                .kind = if (t.kind == .audio) "audio" else "video",
                .mid = t.midText(),
                .direction = dir,
                .codecs = if (t.kind == .audio) &audio_codec else &video_codec,
                .ssrc = if (t.send) t.local_ssrc else 0,
                .cname = &pc.cname,
                .stream_id = "reseal",
                .track_id = if (t.kind == .audio) "audio0" else "video0",
                .rtcp_rsize = t.kind == .video,
                .extmaps = if (t.kind == .video) video_ext[0..video_ext_n] else &.{},
                .rejected = !t.accepted,
            };
            n += 1;
        }
        var cands: std.ArrayList([]const u8) = .empty;
        defer {
            for (cands.items) |c| gpa.free(c);
            cands.deinit(gpa);
        }
        for (pc.local_candidates.items) |c| try cands.append(gpa, try gpa.dupe(u8, c));
        const desc: sdp.Description = .{
            .session_id = pc.session_id,
            .version = pc.session_version,
            .ice_ufrag = pc.transport.ice.localUfrag(),
            .ice_pwd = pc.transport.ice.localPwd(),
            .fingerprint = certs.formatFingerprint(pc.cert.fingerprint, &fp_buf),
            // actpass only before the DTLS role is fixed; afterwards keep it (RFC 8842 5.3).
            .setup = if (pc.transport.dtls) |d| (if (d.isClient()) .active else .passive) else if (pc.offerer) .actpass else .active,
            .media = media[0..n],
            .candidates = cands.items,
            .end_of_candidates = pc.gathering_done,
        };
        var out: std.Io.Writer.Allocating = .init(gpa);
        errdefer out.deinit();
        try sdp.write(desc, &out.writer);
        return out.toOwnedSlice();
    }

    pub fn setRemoteDescription(pc: *PeerConnection, kind: SdpType, text: []const u8, now: u64) !void {
        pc.now = now;
        var s = try sdp.Session.parse(pc.gpa, text);
        defer s.deinit();
        if (s.media.len == 0) return error.NoMedia;
        switch (kind) {
            .offer => {
                if (pc.signaling != .stable) return error.InvalidState;
                // Roles are fixed by the first exchange; a re-offer keeps them.
                if (pc.transport.dtls == null) {
                    pc.offerer = false;
                    pc.transport.ice.setRole(.controlled);
                }
                try pc.acceptOffer(&s);
                pc.signaling = .have_remote_offer;
            },
            .answer => {
                if (pc.signaling != .have_local_offer) return error.InvalidState;
                try pc.acceptAnswer(&s);
                pc.signaling = .stable;
            },
        }
        // ICE credentials and DTLS fingerprint: BUNDLE means the first m-line's apply to all.
        const first = &s.media[0];
        const ufrag = s.mediaAttr(first, "ice-ufrag") orelse return error.MissingIceCredentials;
        const pwd = s.mediaAttr(first, "ice-pwd") orelse return error.MissingIceCredentials;
        const fp_attr = s.mediaAttr(first, "fingerprint") orelse return error.MissingFingerprint;
        const fp = sdp.splitFingerprint(fp_attr) orelse return error.MissingFingerprint;
        if (!std.ascii.eqlIgnoreCase(fp.algorithm, "sha-256")) return error.UnsupportedFingerprint;
        pc.transport.setRemoteFingerprint(try certs.parseFingerprint(fp.value));
        // New credentials in an offer: the peer restarted ICE, and our answer restarts too.
        if (kind == .offer and pc.transport.ice.remoteCredentialsChanged(ufrag, pwd)) pc.restartIceNow();
        try pc.transport.ice.setRemoteCredentials(ufrag, pwd);
        for (s.media) |*m| {
            var it = m.attrs("candidate");
            while (it.next()) |c| {
                var line_buf: [512]u8 = undefined;
                const line = std.fmt.bufPrint(&line_buf, "candidate:{s}", .{c}) catch continue;
                pc.addIceCandidate(line) catch {};
            }
        }
        if (kind == .answer) {
            const setup = first.attr("setup") orelse "active";
            pc.transport.setDtlsRole(if (std.mem.eql(u8, setup, "passive")) .client else .server);
        }
    }

    fn acceptOffer(pc: *PeerConnection, s: *const sdp.Session) !void {
        if (s.media.len > max_mlines) return error.TooManyMediaSections;
        for (&pc.tracks) |*t| {
            t.accepted = false;
            t.mid_len = 0;
        }
        pc.mline_count = 0;
        for (s.media) |*m| {
            const mid = m.mid() orelse return error.MissingMid;
            const kind: ?Kind = if (std.mem.eql(u8, m.kind, "audio")) .audio else if (std.mem.eql(u8, m.kind, "video")) .video else null;
            // One track per kind; anything else (data channels, extra tracks) is rejected
            // with a port-0 m-line so the answer still mirrors the offer.
            if (kind == null or pc.tracks[@backingInt(kind.?)].mid_len != 0) {
                var ml: MLine = .{ .track = null };
                ml.kind.set(m.kind);
                ml.mid.set(mid);
                ml.proto.set(m.proto);
                ml.formats.set(m.formats);
                pc.mlines[pc.mline_count] = ml;
                pc.mline_count += 1;
                continue;
            }
            const t = &pc.tracks[@backingInt(kind.?)];
            pc.mlines[pc.mline_count] = .{ .track = @backingInt(kind.?) };
            pc.mline_count += 1;
            t.setMid(mid);
            const k = kind.?;
            const enabled = if (k == .audio) pc.config.audio else pc.config.video;
            const pt = if (k == .audio) findOpus(m) else findH264(m);
            if (!enabled or pt == null or m.port == 0) continue;
            t.accepted = true;
            t.pt = pt.?;
            const dir = m.direction();
            t.send = dir == .sendrecv or dir == .recvonly;
            t.recv = dir == .sendrecv or dir == .sendonly;
            t.remote_nack = m.hasFeedback(t.pt, "nack");
            if (k == .video) {
                t.cvo_id = m.extmapId(cvo_uri) orelse 0;
                t.abs_id = m.extmapId(abs_send_time_uri) orelse 0;
            }
            try pc.noteRemoteSsrcs(k, m);
        }
    }

    fn acceptAnswer(pc: *PeerConnection, s: *const sdp.Session) !void {
        for (&pc.tracks) |*t| {
            if (!t.accepted) continue;
            const m = for (s.media) |*m| {
                if (std.mem.eql(u8, m.mid() orelse "", t.midText())) break m;
            } else {
                t.accepted = false;
                continue;
            };
            if (m.port == 0) {
                t.accepted = false;
                continue;
            }
            const pt = if (t.kind == .audio) findOpus(m) else findH264(m);
            if (pt == null or pt.? != t.pt) {
                t.accepted = false;
                continue;
            }
            const dir = m.direction();
            t.send = dir == .sendrecv or dir == .recvonly;
            t.recv = dir == .sendrecv or dir == .sendonly;
            t.remote_nack = m.hasFeedback(t.pt, "nack");
            if (t.kind == .video) {
                t.cvo_id = m.extmapId(cvo_uri) orelse 0;
                t.abs_id = m.extmapId(abs_send_time_uri) orelse 0;
            }
            try pc.noteRemoteSsrcs(t.kind, m);
        }
    }

    fn noteRemoteSsrcs(pc: *PeerConnection, kind: Kind, m: *const sdp.Media) !void {
        var buf: [8]u32 = undefined;
        for (m.ssrcs(&buf)) |ssrc| try pc.remote_ssrcs[@backingInt(kind)].append(pc.gpa, ssrc);
    }

    fn findOpus(m: *const sdp.Media) ?u8 {
        var it = m.payloadTypes();
        while (it.next()) |p| {
            const pt = std.fmt.parseInt(u8, p, 10) catch continue;
            const c = m.codec(pt) orelse continue;
            if (std.ascii.eqlIgnoreCase(c.name, "opus") and c.clock == 48000) return pt;
        }
        return null;
    }

    /// Prefers constrained baseline (42e0xx), then baseline (4200xx), packetization-mode 1.
    fn findH264(m: *const sdp.Media) ?u8 {
        var best: ?u8 = null;
        var best_rank: u8 = 0;
        var it = m.payloadTypes();
        while (it.next()) |p| {
            const pt = std.fmt.parseInt(u8, p, 10) catch continue;
            const c = m.codec(pt) orelse continue;
            if (!std.ascii.eqlIgnoreCase(c.name, "H264")) continue;
            if (!std.mem.eql(u8, c.param("packetization-mode") orelse "0", "1")) continue;
            const profile = c.param("profile-level-id") orelse "42e01f";
            const rank: u8 = if (std.ascii.startsWithIgnoreCase(profile, "42e0")) 3 else if (std.ascii.startsWithIgnoreCase(profile, "4200")) 2 else 1;
            if (rank > best_rank) {
                best = pt;
                best_rank = rank;
            }
        }
        return best;
    }

    /// Puts track `i` into the session: its rejected m-line again, or a new one with a fresh mid.
    fn addTrackLine(pc: *PeerConnection, i: u1) void {
        const t = &pc.tracks[i];
        if (t.mid_len == 0) {
            if (pc.mline_count == max_mlines) return;
            var n: u32 = 0;
            var buf: [12]u8 = undefined;
            const mid = while (true) : (n += 1) {
                const text = std.fmt.bufPrint(&buf, "{d}", .{n}) catch return;
                const used = for (pc.mlines[0..pc.mline_count]) |*ml| {
                    const m = if (ml.track) |k| pc.tracks[k].midText() else ml.mid.text();
                    if (std.mem.eql(u8, m, text)) break true;
                } else false;
                if (!used) break text;
            };
            t.setMid(mid);
            pc.mlines[pc.mline_count] = .{ .track = i };
            pc.mline_count += 1;
        }
        t.accepted = true;
        t.pt = if (t.kind == .audio) opus_pt_default else h264_pt_default;
        if (t.kind == .video) {
            t.cvo_id = cvo_default_id;
            t.abs_id = abs_send_time_default_id;
        }
    }

    /// True when our video can go out (negotiated, and the peer accepts it).
    pub fn canSendVideo(pc: *const PeerConnection) bool {
        return pc.tracks[1].accepted and pc.tracks[1].send;
    }

    /// Undoes our pending offer (perfect negotiation: the polite side gives way when both
    /// offered at once). A first offer is forgotten entirely; a re-offer leaves the session as
    /// negotiated before it.
    pub fn rollback(pc: *PeerConnection) void {
        if (pc.signaling != .have_local_offer) return;
        pc.signaling = .stable;
        if (pc.transport.dtls == null and !pc.answered_once) {
            pc.offerer = false;
            pc.mline_count = 0;
            for (&pc.tracks) |*t| {
                t.accepted = false;
                t.mid_len = 0;
                t.cvo_id = 0;
            }
        }
    }

    /// Asks for an ICE restart: the next `createOffer` carries new ICE credentials and the
    /// candidates are signalled again. DTLS and SRTP continue over the new path.
    pub fn restartIce(pc: *PeerConnection) void {
        pc.restart_pending = true;
    }

    fn restartIceNow(pc: *PeerConnection) void {
        for (pc.local_candidates.items) |c| pc.gpa.free(c);
        pc.local_candidates.clearRetainingCapacity();
        pc.transport.ice.restart();
    }

    pub fn isStable(pc: *const PeerConnection) bool {
        return pc.signaling == .stable;
    }

    /// The mid of the first m-line, for RTCIceCandidateInit.sdpMid (BUNDLE: all share it).
    pub fn firstMid(pc: *const PeerConnection) []const u8 {
        if (pc.mline_count == 0) return "0";
        const ml = &pc.mlines[0];
        return if (ml.track) |i| pc.tracks[i].midText() else ml.mid.text();
    }

    pub fn iceUfrag(pc: *const PeerConnection) []const u8 {
        return pc.transport.ice.localUfrag();
    }

    /// Which media the peer sends us, per the negotiated session.
    pub fn remoteSends(pc: *const PeerConnection, kind: Kind) bool {
        const t = &pc.tracks[@backingInt(kind)];
        return t.accepted and t.recv;
    }

    /// Rotation to send with our video (degrees clockwise the receiver turns it: 0, 90, 180,
    /// 270), e.g. the camera sensor's orientation relative to the screen.
    pub fn setVideoRotation(pc: *PeerConnection, degrees: u16) void {
        pc.video_rotation = degrees % 360;
    }

    /// A trickled remote candidate ("candidate:..." with or without "a="). Empty strings
    /// (end of candidates) are ignored.
    pub fn addIceCandidate(pc: *PeerConnection, line: []const u8) !void {
        const trimmed = std.mem.trim(u8, line, " \r\n");
        if (trimmed.len == 0) return;
        const c = candidate.Candidate.parse(trimmed) catch |err| switch (err) {
            error.UnsupportedTransport => return,
            else => return err,
        };
        try pc.transport.ice.addRemoteCandidate(c);
    }

    // ---- I/O -----------------------------------------------------------------------------

    pub fn receive(pc: *PeerConnection, socket: u8, from: net.Address, data: []const u8, now: u64) void {
        pc.now = now;
        pc.transport.receive(socket, from, data, now);
        pc.drainJitter(now);
    }

    pub fn poll(pc: *PeerConnection, now: u64) void {
        pc.now = now;
        pc.transport.poll(now);
        pc.drainJitter(now);
        pc.sendNacks(now);
        if (pc.srtp_send != null and now >= pc.next_rtcp_at) {
            pc.next_rtcp_at = now + 1000;
            pc.sendReports(now);
        }
    }

    pub fn nextTimeout(pc: *const PeerConnection) ?u64 {
        var t = pc.transport.nextTimeout();
        if (pc.srtp_send != null) t = if (t) |v| @min(v, pc.next_rtcp_at) else pc.next_rtcp_at;
        // Jitter buffers and NACKs need a regular look while media flows.
        if (pc.streams.items.len > 0) t = if (t) |v| @min(v, pc.now + 20) else pc.now + 20;
        return t;
    }

    pub fn connectionState(pc: *const PeerConnection) ConnectionState {
        return pc.transport.state;
    }

    pub fn close(pc: *PeerConnection) void {
        if (pc.srtp_send != null) {
            var buf: [128]u8 = undefined;
            var b: rtcp.Builder = .{ .buf = &buf };
            b.bye(pc.tracks[0].local_ssrc) catch {};
            pc.sendRtcp(&b);
        }
        pc.transport.close();
    }

    // ---- sending media -------------------------------------------------------------------

    /// Sends one Opus packet; the RTP timestamp advances by the packet's duration.
    pub fn sendAudio(pc: *PeerConnection, packet: []const u8) !void {
        const t = &pc.tracks[0];
        if (!t.accepted or !t.send) return error.NotNegotiated;
        const samples = try opus.packetSamples(packet);
        try pc.sendRtp(t, packet, t.timestamp, !t.sent_any);
        t.timestamp +%= samples;
    }

    /// Sends one H.264 access unit (Annex-B) with a 90 kHz timestamp.
    pub fn sendVideo(pc: *PeerConnection, annexb: []const u8, timestamp_90k: u32) !void {
        const t = &pc.tracks[1];
        if (!t.accepted or !t.send) return error.NotNegotiated;
        if (pc.srtp_send == null) return error.NotConnected;
        const Ctx = struct { pc: *PeerConnection, ts: u32, err: ?anyerror = null };
        var ctx: Ctx = .{ .pc = pc, .ts = timestamp_90k };
        h264.packetize(annexb, max_rtp_payload, &ctx, struct {
            fn f(c: *Ctx, payload: []const u8, marker: bool) void {
                c.pc.sendRtp(&c.pc.tracks[1], payload, c.ts, marker) catch |e| {
                    c.err = e;
                };
            }
        }.f);
        if (ctx.err) |e| return e;
    }

    fn sendRtp(pc: *PeerConnection, t: *Track, payload: []const u8, ts: u32, marker: bool) !void {
        const ctx = &(pc.srtp_send orelse return error.NotConnected);
        var buf: [1500]u8 = undefined;
        var elements: [2]rtp.Element = undefined;
        var ne: usize = 0;
        var abs: [3]u8 = undefined;
        const cvo = [1]u8{@intCast(pc.video_rotation / 90 % 4)};
        if (t.kind == .video) {
            if (t.abs_id != 0) {
                // 6.18 fixed-point seconds, 24 bits (only differences matter to the receiver).
                std.mem.writeInt(u24, &abs, @truncate((pc.now << 18) / 1000), .big);
                elements[ne] = .{ .id = @intCast(t.abs_id), .data = &abs };
                ne += 1;
            }
            if (t.cvo_id != 0 and marker) {
                elements[ne] = .{ .id = @intCast(t.cvo_id), .data = &cvo };
                ne += 1;
            }
        }
        const n = try rtp.writeWithElements(&buf, marker, @intCast(t.pt), t.seq, ts, t.local_ssrc, elements[0..ne], payload);
        const len = try ctx.protectRtp(&buf, n);
        if (t.kind == .video) {
            const h = &pc.history[pc.history_next];
            h.seq = t.seq;
            h.len = @intCast(len);
            @memcpy(h.data[0..len], buf[0..len]);
            pc.history_next = (pc.history_next + 1) % history_len;
        }
        if (t.kind == .video) pc.sent_window += 1;
        if (!(t.kind == .video and pc.dropForTest())) pc.transport.sendMedia(buf[0..len]);
        t.seq +%= 1;
        t.packets +%= 1;
        t.octets +%= @intCast(payload.len);
        t.last_rtp_ts = ts;
        t.last_send_ms = pc.now;
        t.sent_any = true;
    }

    /// Asks the peer for a keyframe on every video stream it sends us (PLI).
    pub fn requestKeyframe(pc: *PeerConnection) void {
        for (pc.streams.items) |*s| if (s.kind == .video) pc.sendPli(s, true);
    }

    fn sendPli(pc: *PeerConnection, s: *RemoteStream, force: bool) void {
        if (!force and pc.now < s.last_pli_at + 300) return;
        s.last_pli_at = pc.now;
        var buf: [64]u8 = undefined;
        var b: rtcp.Builder = .{ .buf = &buf };
        b.pli(pc.tracks[1].local_ssrc, s.ssrc) catch return;
        pc.sendRtcp(&b);
    }

    fn sendRtcp(pc: *PeerConnection, b: *rtcp.Builder) void {
        const ctx = &(pc.srtp_send orelse return);
        var buf: [1500]u8 = undefined;
        if (b.len + 20 > buf.len) return;
        @memcpy(buf[0..b.len], b.bytes());
        const n = ctx.protectRtcp(&buf, b.len) catch return;
        pc.transport.sendMedia(buf[0..n]);
    }

    fn sendNacks(pc: *PeerConnection, now: u64) void {
        if (!pc.tracks[1].remote_nack and !pc.tracks[1].accepted) return;
        for (pc.streams.items) |*s| {
            if (s.kind != .video or now < s.last_nack_at + 50) continue;
            var lost: [32]u16 = undefined;
            const list = s.jitter.missing(&lost);
            if (list.len == 0) continue;
            s.last_nack_at = now;
            var buf: [256]u8 = undefined;
            var b: rtcp.Builder = .{ .buf = &buf };
            b.nack(pc.tracks[1].local_ssrc, s.ssrc, list) catch continue;
            pc.sendRtcp(&b);
        }
    }

    /// SR (if sending) or RR with report blocks, SDES CNAME, and REMB for received video.
    fn sendReports(pc: *PeerConnection, now: u64) void {
        var blocks: [8]rtcp.ReportBlock = undefined;
        var nb: usize = 0;
        for (pc.streams.items) |*s| {
            if (nb == blocks.len) break;
            blocks[nb] = pc.reportBlock(s, now);
            nb += 1;
        }
        var buf: [1200]u8 = undefined;
        var b: rtcp.Builder = .{ .buf = &buf };
        const unix_ms: u64 = @intCast(@divTrunc(std.Io.Timestamp.now(pc.io, .real).nanoseconds, std.time.ns_per_ms));
        var first = true;
        for (&pc.tracks) |*t| {
            if (!t.sent_any) continue;
            const clock: u64 = if (t.kind == .audio) 48 else 90;
            const rtp_now = t.last_rtp_ts +% @as(u32, @truncate((now -| t.last_send_ms) * clock));
            b.senderReport(t.local_ssrc, rtcp.ntpFromUnixMs(unix_ms), rtp_now, t.packets, t.octets, if (first) blocks[0..nb] else &.{}) catch return;
            first = false;
        }
        const sender = if (pc.tracks[0].sent_any or !pc.tracks[1].sent_any) pc.tracks[0].local_ssrc else pc.tracks[1].local_ssrc;
        if (first) b.receiverReport(sender, blocks[0..nb]) catch return;
        b.sdesCname(sender, &pc.cname) catch return;
        var video_ssrcs: [4]u32 = undefined;
        var nv: usize = 0;
        for (pc.streams.items) |s| if (s.kind == .video and nv < video_ssrcs.len) {
            video_ssrcs[nv] = s.ssrc;
            nv += 1;
        };
        if (nv > 0) b.remb(sender, pc.config.max_video_bitrate, video_ssrcs[0..nv]) catch {};
        pc.sendRtcp(&b);
    }

    fn reportBlock(pc: *const PeerConnection, s: *RemoteStream, now: u64) rtcp.ReportBlock {
        _ = pc;
        const base = s.base_seq orelse return .{ .ssrc = s.ssrc };
        const expected = s.max_seq - base + 1;
        const lost: i64 = @as(i64, @intCast(expected)) - @as(i64, @intCast(s.received));
        const exp_int = expected - s.expected_prior;
        const rec_int = s.received - s.received_prior;
        s.expected_prior = expected;
        s.received_prior = s.received;
        const lost_int: i64 = @as(i64, @intCast(exp_int)) - @as(i64, @intCast(rec_int));
        const fraction: u8 = if (exp_int == 0 or lost_int <= 0) 0 else @intCast(@min(255, @divTrunc(lost_int << 8, @as(i64, @intCast(exp_int)))));
        return .{
            .ssrc = s.ssrc,
            .fraction_lost = fraction,
            .cumulative_lost = @intCast(std.math.clamp(lost, 0, 0x7fffff)),
            .highest_seq = @truncate(s.max_seq),
            .jitter = s.jitter_q4 >> 4,
            .last_sr = s.last_sr_mid,
            .delay_since_last_sr = if (s.last_sr_at == 0) 0 else @truncate(((now - s.last_sr_at) * 65536) / 1000),
        };
    }

    // ---- receiving media -----------------------------------------------------------------

    fn onMedia(ctx: *anyopaque, data: []const u8) void {
        const pc: *PeerConnection = @ptrCast(@alignCast(ctx));
        const recv = &(pc.srtp_recv orelse return);
        var buf: [1500]u8 = undefined;
        if (data.len > buf.len) return;
        @memcpy(buf[0..data.len], data);
        if (rtp.isRtcp(data)) {
            const n = recv.unprotectRtcp(buf[0..data.len]) catch {
                pc.srtp_errors += 1;
                return;
            };
            pc.handleRtcp(buf[0..n]);
        } else {
            const n = recv.unprotectRtp(buf[0..data.len]) catch {
                pc.srtp_errors += 1;
                return;
            };
            const p = rtp.Packet.parse(buf[0..n]) catch return;
            pc.handleRtp(p);
        }
    }

    fn streamFor(pc: *PeerConnection, p: rtp.Packet) ?*RemoteStream {
        for (pc.streams.items) |*s| if (s.ssrc == p.ssrc) return s;
        // New SSRC: classify by announced SSRC, else by payload type.
        const kind: Kind = blk: {
            for (pc.remote_ssrcs, 0..) |list, k| if (std.mem.indexOfScalar(u32, list.items, p.ssrc) != null) break :blk @fromBackingInt(@intCast(k));
            if (pc.tracks[0].accepted and p.payload_type == pc.tracks[0].pt) break :blk .audio;
            if (pc.tracks[1].accepted and p.payload_type == pc.tracks[1].pt) break :blk .video;
            return null;
        };
        const t = &pc.tracks[@backingInt(kind)];
        if (!t.accepted or p.payload_type != t.pt) return null;
        pc.streams.append(pc.gpa, .{
            .ssrc = p.ssrc,
            .kind = kind,
            .clock = if (kind == .audio) 48000 else 90000,
            .jitter = .init(pc.gpa, if (kind == .audio) .audio else .video, if (kind == .audio) pc.config.audio_jitter_ms else pc.config.video_jitter_ms),
        }) catch return null;
        return &pc.streams.items[pc.streams.items.len - 1];
    }

    fn handleRtp(pc: *PeerConnection, p: rtp.Packet) void {
        const s = pc.streamFor(p) orelse return;
        if (p.payload_type != pc.tracks[@backingInt(s.kind)].pt) return;
        if (s.kind == .video and pc.tracks[1].cvo_id != 0) {
            if (p.extensionElement(@intCast(pc.tracks[1].cvo_id))) |v| s.rotation = @as(u16, v[0] & 3) * 90;
        }
        // Statistics (RFC 3550 A.3, A.8).
        const ext = if (s.base_seq == null) @as(u64, p.seq) + 0x10000 else rtp.extendSeq(s.max_seq, p.seq);
        if (s.base_seq == null) {
            s.base_seq = ext;
            s.max_seq = ext;
        }
        s.max_seq = @max(s.max_seq, ext);
        s.received += 1;
        s.bytes += p.payload.len;
        const arrival: i64 = @intCast((pc.now * s.clock) / 1000);
        const transit = arrival - @as(i64, @intCast(p.timestamp));
        if (s.transit) |prev| {
            const d: u32 = @intCast(@min(@abs(transit - prev), std.math.maxInt(u32) / 16));
            s.jitter_q4 = s.jitter_q4 +% d -% ((s.jitter_q4 + 8) >> 4);
        }
        s.transit = transit;
        if (p.payload.len == 0) return; // padding-only probe
        _ = s.jitter.push(p.seq, p.timestamp, p.marker, p.payload, pc.now) catch return;
    }

    fn drainJitter(pc: *PeerConnection, now: u64) void {
        for (pc.streams.items) |*s| {
            while (s.jitter.pop(now)) |f| {
                s.frames += 1;
                switch (s.kind) {
                    .audio => for (f.payloads) |payload| pc.emit(.{ .audio_frame = .{ .ssrc = s.ssrc, .timestamp = f.timestamp, .data = payload } }),
                    .video => {
                        pc.depacketizer.reset();
                        for (f.payloads) |payload| pc.depacketizer.push(pc.gpa, payload) catch {};
                        const data = pc.depacketizer.frame();
                        const corrupt = pc.depacketizer.corrupt or f.discontinuity;
                        const key = data.len > 0 and h264.isKeyframe(data);
                        if (corrupt and !key) pc.sendPli(s, false);
                        if (data.len > 0) pc.emit(.{ .video_frame = .{ .ssrc = s.ssrc, .timestamp = f.timestamp, .data = data, .keyframe = key, .corrupt = corrupt, .rotation = s.rotation } });
                    },
                }
            }
        }
    }

    fn handleRtcp(pc: *PeerConnection, data: []const u8) void {
        var it: rtcp.Iterator = .{ .data = data };
        while (it.next()) |p| {
            switch (p.type) {
                .sr => if (p.senderInfo()) |info| {
                    for (pc.streams.items) |*s| if (s.ssrc == p.senderSsrc()) {
                        s.last_sr_mid = @truncate(info.ntp >> 16);
                        s.last_sr_at = pc.now;
                    };
                    pc.onReportBlocks(p);
                },
                .rr => pc.onReportBlocks(p),
                .rtpfb => if (p.isNack() and p.mediaSsrc() == pc.tracks[1].local_ssrc) {
                    var lost: [128]u16 = undefined;
                    for (p.nackList(&lost)) |seq| {
                        pc.nacked_window += 1;
                        pc.retransmit(seq);
                    }
                },
                .psfb => {
                    if (p.isPli() and p.mediaSsrc() == pc.tracks[1].local_ssrc) pc.emit(.keyframe_requested);
                    if (p.firTarget()) |target| if (target == pc.tracks[1].local_ssrc) pc.emit(.keyframe_requested);
                    if (p.rembBitrate()) |rate| {
                        pc.remote_bitrate = rate;
                        pc.emit(.{ .remote_bitrate = rate });
                        pc.bitrate.onRemb(pc.now, rate);
                        pc.emitBitrate(false);
                    }
                },
                else => {},
            }
        }
    }

    fn retransmit(pc: *PeerConnection, seq: u16) void {
        for (pc.history) |*h| if (h.len > 0 and h.seq == seq) {
            pc.transport.sendMedia(h.data[0..h.len]);
            return;
        };
    }

    pub fn stats(pc: *const PeerConnection) Stats {
        var s: Stats = .{
            .ice = pc.transport.ice.state,
            .connection = pc.transport.state,
            .srtp_profile = pc.transport.srtpProfile(),
            .local_candidate = null,
            .remote_candidate = null,
            .audio_sent = pc.tracks[0].packets,
            .video_sent = pc.tracks[1].packets,
            .audio_received = 0,
            .video_received = 0,
            .audio_frames = 0,
            .video_frames = 0,
            .srtp_errors = pc.srtp_errors,
            .remote_bitrate = pc.remote_bitrate,
        };
        if (pc.transport.ice.selectedPair()) |p| {
            s.local_candidate = p.local;
            s.remote_candidate = p.remote;
        }
        for (pc.streams.items) |r| switch (r.kind) {
            .audio => {
                s.audio_received += r.received;
                s.audio_frames += r.frames;
            },
            .video => {
                s.video_received += r.received;
                s.video_frames += r.frames;
            },
        };
        return s;
    }
};
