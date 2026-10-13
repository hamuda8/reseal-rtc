//! Call engine for zig-core's zui calls API on the phones. An app enables native calls with
//!
//!     pub const rtc = @import("reseal_rtc").zui_engine;
//!
//! in its client root. zui does capture, encoding, decoding and drawing; this file runs the
//! connection: ICE, DTLS-SRTP, RTP, and the signalling the web host speaks, so a phone and a
//! browser running zui's web host (shells/web/zui.js, RTCPeerConnection) can call each other:
//!
//!   {"description":{"type":"offer"|"answer","sdp":"..."}}
//!   {"candidate":{"candidate":"candidate:...","sdpMid":"0","sdpMLineIndex":0,"usernameFragment":"..."}}
//!
//! Negotiation follows the web host: each side offers as soon as it opens; on a collision the
//! polite side rolls its offer back and answers, the impolite side ignores the other offer;
//! when the connection fails, ICE restarts with a new offer.
//!
//! Threads: `open`, `signal`, `send*`, `requestKeyframe` and `close` may be called from any
//! thread. Sink functions are called from the engine's own threads (or inside those calls)
//! with the connection locked, so they must not call back into the engine.

const std = @import("std");
const peer_mod = @import("peer.zig");
const builtin = @import("builtin");
const driver = @import("driver.zig");
const posix = @import("posix.zig");

/// Phones (and other POSIX systems) run on BSD sockets and threads (posix.zig); Windows, where
/// the tests run during development, on std.Io.Threaded (driver.zig).
const use_posix = builtin.os.tag != .windows;
const Udp = if (use_posix) posix.Udp else driver.UdpSocket;
const Driver = if (use_posix) posix.Driver else driver.Driver;
const net = @import("net.zig");
const IceAgent = @import("ice/Agent.zig");

const PeerConnection = peer_mod.PeerConnection;
const Io = std.Io;

/// Where the engine reports to zui.
pub const Sink = struct {
    ctx: *anyopaque,
    /// JSON for the other side's peerSignal.
    signal: *const fn (ctx: *anyopaque, json: []const u8) void,
    /// "connecting", "connected", "disconnected", "failed" or "closed".
    state: *const fn (ctx: *anyopaque, state: []const u8) void,
    /// What the other side sends us, after each negotiation.
    tracks: *const fn (ctx: *anyopaque, audio: bool, video: bool) void,
    /// One Opus packet (48 kHz).
    audio: *const fn (ctx: *anyopaque, packet: []const u8) void,
    /// One H.264 access unit (Annex-B). `rotation`: degrees clockwise to stand it upright.
    video: *const fn (ctx: *anyopaque, annexb: []const u8, keyframe: bool, rotation: u16) void,
    /// The other side wants a keyframe from our encoder.
    keyframe: *const fn (ctx: *anyopaque) void,
    /// The bitrate our video encoder should use now (bits per second), from the other side's
    /// reports: loss, round-trip time and its bandwidth estimate, with the loss (0..1) behind it
    /// (media steps the resolution down on loss, not on a low but clean estimate). Optional.
    bitrate: ?*const fn (ctx: *anyopaque, bps: u32, loss: f32) void = null,
};

/// Tests only: drop this percentage of outgoing video packets, to watch adaptation work.
pub var test_drop_video_percent: u8 = 0;
/// Tests only: iceTransportPolicy "relay" for the next connections (only TURN candidates).
pub var test_relay_only: bool = false;

pub const Options = struct {
    /// RTCPeerConnection's iceServers JSON: [{"urls":[...],"username":"","credential":""}].
    ice_servers: []const u8 = "[]",
    polite: bool,
    /// Local addresses to bind (host candidates). Empty: the default route's interface.
    bind: []const net.Address = &.{},
};

const max_sockets = 4;

pub const Peer = struct {
    gpa: std.mem.Allocator,
    io: Io,
    sink: Sink,
    polite: bool,
    pc: *PeerConnection = undefined,
    udp: [max_sockets]Udp = undefined,
    udp_count: usize = 0,
    /// TURN over TCP/TLS connections (phones only).
    streams: [max_sockets]*if (use_posix) posix.StreamConn else void = undefined,
    stream_count: usize = 0,
    driver: Driver = undefined,
    servers: []IceAgent.Server = &.{},
    /// Inside a negotiation call: candidates wait so they follow the description they belong to.
    negotiating: bool = false,
    held: std.ArrayList([]u8) = .empty,
    ignore_offer: bool = false,
    restart_wanted: bool = false,
    /// Video was handed to us but the session has none: renegotiate once to add it.
    video_wanted: bool = false,
    video_offered: bool = false,
    connection: peer_mod.ConnectionState = .new,
    ice: peer_mod.IceState = .new,
    reported: []const u8 = "",
    tracks_audio: bool = false,
    tracks_video: bool = false,
};

fn openUdp(io: Io, a: net.Address) !Udp {
    return if (use_posix) Udp.open(a) else Udp.open(io, a);
}

fn nowMs(p: *const Peer) u64 {
    return if (use_posix) posix.nowMs() else driver.nowMs(p.io);
}

fn sleepMs(ms: u64) void {
    if (use_posix) posix.sleepMs(ms) else processIo().sleep(.fromMilliseconds(@intCast(ms)), .awake) catch {};
}

// One Io for every connection in the process, created on first use.
var threaded: Io.Threaded = undefined;
var threaded_ready = false;

fn processIo() Io {
    if (use_posix) return posix.io();
    if (!threaded_ready) {
        threaded = .init(std.heap.smp_allocator, .{});
        threaded_ready = true;
    }
    return threaded.io();
}

/// Opens a connection and sends the first offer (through `sink.signal`).
pub fn open(gpa: std.mem.Allocator, opts: Options, sink: Sink) !*Peer {
    const io = processIo();
    const p = try gpa.create(Peer);
    errdefer gpa.destroy(p);
    p.* = .{ .gpa = gpa, .io = io, .sink = sink, .polite = opts.polite };
    errdefer for (p.udp[0..p.udp_count]) |*u| u.close();

    if (opts.bind.len > 0) {
        for (opts.bind[0..@min(opts.bind.len, max_sockets)]) |a| {
            p.udp[p.udp_count] = try openUdp(io, a);
            p.udp_count += 1;
        }
    } else {
        const found = if (use_posix) posix.defaultLocalAddress() else driver.defaultLocalAddress(io, .ip4);
        p.udp[0] = try openUdp(io, found orelse net.Address.ip4(.{ 0, 0, 0, 0 }, 0));
        p.udp_count = 1;
    }

    p.servers = resolveServers(io, gpa, opts.ice_servers) catch &.{};
    errdefer driver.freeServers(gpa, p.servers);

    var sockets: [2 * max_sockets]net.Socket = undefined;
    for (p.udp[0..p.udp_count], 0..) |*u, i| sockets[i] = u.socket();
    // TURN over TCP or TLS: a stream connection per such server, after the UDP sockets.
    if (use_posix) for (p.servers) |srv| {
        if (!srv.turn or srv.transport == .udp or p.stream_count == max_sockets) continue;
        const sc = try posix.StreamConn.create(gpa, srv.address, srv.host, srv.transport == .tls);
        p.streams[p.stream_count] = sc;
        sockets[p.udp_count + p.stream_count] = sc.socket();
        p.stream_count += 1;
    };
    errdefer if (use_posix) for (p.streams[0..p.stream_count]) |sc| sc.destroy();
    p.pc = try PeerConnection.create(gpa, io, .{
        .sockets = sockets[0 .. p.udp_count + p.stream_count],
        .servers = p.servers,
        .ice_relay_only = test_relay_only,
        .handler = .{ .ctx = p, .onEvent = onEvent },
    });
    errdefer p.pc.destroy();
    p.driver = if (use_posix) .init(p.pc, p.udp[0..p.udp_count]) else .init(io, p.pc, p.udp[0..p.udp_count]);
    p.driver.on_tick = .{ .ctx = p, .f = onTick };
    if (use_posix) p.driver.streams = p.streams[0..p.stream_count];

    // Like the browser's negotiationneeded: offer right away.
    offer(p);
    try p.driver.start();
    return p;
}

/// Stops the connection (RTCP BYE, DTLS close_notify) and frees it.
pub fn close(p: *Peer) void {
    p.driver.stop();
    p.pc.close();
    p.pc.destroy();
    if (use_posix) for (p.streams[0..p.stream_count]) |sc| sc.destroy();
    for (p.udp[0..p.udp_count]) |*u| u.close();
    driver.freeServers(p.gpa, p.servers);
    for (p.held.items) |h| p.gpa.free(h);
    p.held.deinit(p.gpa);
    p.gpa.destroy(p);
}

/// A signal from the other side (its `.signal` JSON).
pub fn signal(p: *Peer, json: []const u8) void {
    const Msg = struct {
        description: ?struct { type: []const u8, sdp: []const u8 } = null,
        candidate: ?struct { candidate: []const u8 = "" } = null,
    };
    const parsed = std.json.parseFromSlice(Msg, p.gpa, json, .{ .ignore_unknown_fields = true }) catch return;
    defer parsed.deinit();
    p.driver.lock();
    defer p.driver.unlock();
    const now = nowMs(p);
    if (parsed.value.description) |d| {
        if (std.mem.eql(u8, d.type, "offer")) {
            const collision = !p.pc.isStable();
            p.ignore_offer = !p.polite and collision;
            if (p.ignore_offer) return;
            p.negotiating = true;
            defer endNegotiation(p);
            if (collision) p.pc.rollback();
            p.pc.setRemoteDescription(.offer, d.sdp, now) catch return;
            const answer = p.pc.createAnswer(p.gpa, now) catch return;
            defer p.gpa.free(answer);
            sendDescription(p, "answer", answer);
            reportTracks(p);
        } else if (std.mem.eql(u8, d.type, "answer")) {
            if (p.pc.isStable()) return; // an answer to an offer we rolled back
            p.negotiating = true;
            defer endNegotiation(p);
            p.pc.setRemoteDescription(.answer, d.sdp, now) catch return;
            reportTracks(p);
        }
    } else if (parsed.value.candidate) |c| {
        p.pc.addIceCandidate(c.candidate) catch {};
    }
}

pub fn sendAudio(p: *Peer, packet: []const u8) void {
    p.driver.lock();
    defer p.driver.unlock();
    p.pc.sendAudio(packet) catch {};
}

/// One H.264 access unit (Annex-B) with its 90 kHz timestamp and the rotation the receiver
/// must apply (degrees clockwise).
pub fn sendVideo(p: *Peer, annexb: []const u8, timestamp_90k: u32, rotation: u16) void {
    p.driver.lock();
    defer p.driver.unlock();
    p.pc.setVideoRotation(rotation);
    p.pc.debug_drop_video_percent = test_drop_video_percent;
    if (!p.pc.canSendVideo()) {
        // A call that began as voice: add video by renegotiating, like addTrack in a browser.
        if (!p.video_offered) {
            p.video_wanted = true;
            onTick(p);
        }
        return;
    }
    p.pc.sendVideo(annexb, timestamp_90k) catch {};
}

/// Asks the other side for a keyframe (after a decoder error, or a new view of its video).
pub fn requestKeyframe(p: *Peer) void {
    p.driver.lock();
    defer p.driver.unlock();
    p.pc.requestKeyframe();
}

/// Forces an ICE restart now (also done automatically when the connection fails).
pub fn restartIce(p: *Peer) void {
    p.driver.lock();
    defer p.driver.unlock();
    p.restart_wanted = true;
    onTick(p);
}

// ---- inside the lock ------------------------------------------------------------------------

fn offer(p: *Peer) void {
    p.negotiating = true;
    defer endNegotiation(p);
    const sdp = p.pc.createOffer(p.gpa, nowMs(p)) catch return;
    defer p.gpa.free(sdp);
    sendDescription(p, "offer", sdp);
}

fn endNegotiation(p: *Peer) void {
    p.negotiating = false;
    const held = p.held.toOwnedSlice(p.gpa) catch return;
    defer p.gpa.free(held);
    for (held) |h| {
        p.sink.signal(p.sink.ctx, h);
        p.gpa.free(h);
    }
}

fn sendDescription(p: *Peer, kind: []const u8, sdp: []const u8) void {
    const json = std.json.Stringify.valueAlloc(p.gpa, .{ .description = .{ .type = kind, .sdp = sdp } }, .{}) catch return;
    defer p.gpa.free(json);
    p.sink.signal(p.sink.ctx, json);
}

fn reportTracks(p: *Peer) void {
    const a = p.pc.remoteSends(.audio);
    const v = p.pc.remoteSends(.video);
    if (a == p.tracks_audio and v == p.tracks_video) return;
    p.tracks_audio = a;
    p.tracks_video = v;
    p.sink.tracks(p.sink.ctx, a, v);
}

fn onTick(ctx: *anyopaque) void {
    const p: *Peer = @ptrCast(@alignCast(ctx));
    if (p.video_wanted and p.pc.isStable() and !p.restart_wanted) {
        p.video_wanted = false;
        p.video_offered = true;
        offer(p);
        return;
    }
    // Restart ICE once the connection failed, as the web host does (pc.restartIce()). If an
    // offer is in flight, the restart waits for it to settle.
    if (p.restart_wanted and p.pc.isStable()) {
        p.restart_wanted = false;
        p.pc.restartIce();
        offer(p);
    }
}

fn report(p: *Peer) void {
    // The browser's connectionState: ICE "disconnected" shows while DTLS stays up.
    const text: []const u8 = switch (p.connection) {
        .new => return,
        .connecting => "connecting",
        .connected => if (p.ice == .disconnected) "disconnected" else "connected",
        .failed => "failed",
        .closed => "closed",
    };
    if (std.mem.eql(u8, text, p.reported)) return;
    p.reported = text;
    p.sink.state(p.sink.ctx, text);
}

fn onEvent(ctx: *anyopaque, e: peer_mod.Event) void {
    const p: *Peer = @ptrCast(@alignCast(ctx));
    switch (e) {
        .local_candidate => |line| {
            const json = std.json.Stringify.valueAlloc(p.gpa, .{ .candidate = .{
                .candidate = line,
                .sdpMid = p.pc.firstMid(),
                .sdpMLineIndex = @as(u32, 0),
                .usernameFragment = p.pc.iceUfrag(),
            } }, .{}) catch return;
            if (p.negotiating) {
                p.held.append(p.gpa, json) catch p.gpa.free(json);
            } else {
                defer p.gpa.free(json);
                p.sink.signal(p.sink.ctx, json);
            }
        },
        .connection_state => |s| {
            p.connection = s;
            if (s == .failed) p.restart_wanted = true;
            report(p);
        },
        .ice_state => |s| {
            p.ice = s;
            if (s == .failed) p.restart_wanted = true;
            report(p);
        },
        .audio_frame => |f| p.sink.audio(p.sink.ctx, f.data),
        .video_frame => |f| p.sink.video(p.sink.ctx, f.data, f.keyframe, f.rotation),
        .keyframe_requested => p.sink.keyframe(p.sink.ctx),
        .send_bitrate => |b| if (p.sink.bitrate) |f| f(p.sink.ctx, b.bps, b.loss),
        .gathering_done, .remote_bitrate => {},
    }
}

/// iceServers JSON (urls as a string or a list) to resolved servers.
fn resolveServers(io: Io, gpa: std.mem.Allocator, json: []const u8) ![]IceAgent.Server {
    const parsed = try std.json.parseFromSlice(std.json.Value, gpa, json, .{});
    defer parsed.deinit();
    if (parsed.value != .array) return error.BadIceServers;
    var list: std.ArrayList(driver.IceServerUrls) = .empty;
    defer list.deinit(gpa);
    var urls_storage: std.ArrayList([]const u8) = .empty;
    defer urls_storage.deinit(gpa);
    // Collect all urls first so the slices below stay valid.
    var spans: std.ArrayList(struct { start: usize, len: usize, user: []const u8, cred: []const u8 }) = .empty;
    defer spans.deinit(gpa);
    for (parsed.value.array.items) |entry| {
        if (entry != .object) continue;
        const start = urls_storage.items.len;
        if (entry.object.get("urls")) |u| switch (u) {
            .string => |s| try urls_storage.append(gpa, s),
            .array => |a| for (a.items) |x| if (x == .string) try urls_storage.append(gpa, x.string),
            else => {},
        };
        const user = if (entry.object.get("username")) |v| (if (v == .string) v.string else "") else "";
        const cred = if (entry.object.get("credential")) |v| (if (v == .string) v.string else "") else "";
        try spans.append(gpa, .{ .start = start, .len = urls_storage.items.len - start, .user = user, .cred = cred });
    }
    for (spans.items) |s| try list.append(gpa, .{ .urls = urls_storage.items[s.start..][0..s.len], .username = s.user, .credential = s.cred });
    if (use_posix) return posix.resolveIceServers(gpa, list.items);
    return driver.resolveIceServers(io, gpa, list.items);
}

// ---- tests ----------------------------------------------------------------------------------

const testing = std.testing;

const Spin = struct {
    m: std.atomic.Mutex = .unlocked,
    fn lock(s: *Spin) void {
        while (!s.m.tryLock()) std.atomic.spinLoopHint();
    }
    fn unlock(s: *Spin) void {
        s.m.unlock();
    }
};

/// One side of the test: what its engine reported, and signals waiting for the other side.
const Side = struct {
    spin: Spin = .{},
    outbox: std.ArrayList([]u8) = .empty,
    states: std.ArrayList(u8) = .empty, // last state's first letter per report
    connected: bool = false,
    audio: u32 = 0,
    video: u32 = 0,
    tracks_video: bool = false,
    keyframes: u32 = 0,
    offers: u32 = 0,

    fn sink(s: *Side) Sink {
        return .{ .ctx = s, .signal = onSignal, .state = onState, .tracks = onTracks, .audio = onAudio, .video = onVideo, .keyframe = onKeyframe };
    }
    fn onSignal(ctx: *anyopaque, json: []const u8) void {
        const s: *Side = @ptrCast(@alignCast(ctx));
        s.spin.lock();
        defer s.spin.unlock();
        if (std.mem.indexOf(u8, json, "\"type\":\"offer\"") != null) s.offers += 1;
        s.outbox.append(testing.allocator, testing.allocator.dupe(u8, json) catch unreachable) catch unreachable;
    }
    fn onState(ctx: *anyopaque, st: []const u8) void {
        const s: *Side = @ptrCast(@alignCast(ctx));
        s.spin.lock();
        defer s.spin.unlock();
        s.connected = std.mem.eql(u8, st, "connected");
    }
    fn onTracks(ctx: *anyopaque, _: bool, v: bool) void {
        const s: *Side = @ptrCast(@alignCast(ctx));
        s.tracks_video = v;
    }
    fn onAudio(ctx: *anyopaque, _: []const u8) void {
        const s: *Side = @ptrCast(@alignCast(ctx));
        s.spin.lock();
        defer s.spin.unlock();
        s.audio += 1;
    }
    fn onVideo(ctx: *anyopaque, _: []const u8, _: bool, rotation: u16) void {
        const s: *Side = @ptrCast(@alignCast(ctx));
        s.spin.lock();
        defer s.spin.unlock();
        if (rotation == 90) s.video += 1;
    }
    fn onKeyframe(ctx: *anyopaque) void {
        const s: *Side = @ptrCast(@alignCast(ctx));
        s.keyframes += 1;
    }
    fn take(s: *Side) []([]u8) {
        s.spin.lock();
        defer s.spin.unlock();
        return s.outbox.toOwnedSlice(testing.allocator) catch unreachable;
    }
    fn isConnected(s: *Side) bool {
        s.spin.lock();
        defer s.spin.unlock();
        return s.connected;
    }
    fn deinit(s: *Side) void {
        for (s.outbox.items) |m| testing.allocator.free(m);
        s.outbox.deinit(testing.allocator);
        s.states.deinit(testing.allocator);
    }
};

fn relay(from: *Side, to: *Peer) void {
    const msgs = from.take();
    defer testing.allocator.free(msgs);
    for (msgs) |m| {
        signal(to, m);
        testing.allocator.free(m);
    }
}

fn waitConnected(sides: *[2]Side, peers: [2]*Peer, ms: u32) !void {
    var waited: u32 = 0;
    while (waited < ms) : (waited += 10) {
        relay(&sides[0], peers[1]);
        relay(&sides[1], peers[0]);
        if (sides[0].isConnected() and sides[1].isConnected()) return;
        sleepMs(10);
    }
    return error.NotConnected;
}

test "two engines: glare resolved by perfect negotiation, media, ICE restart" {
    const gpa = testing.allocator;
    var sides = [2]Side{ .{}, .{} };
    defer for (&sides) |*s| s.deinit();
    const lo = [_]net.Address{net.Address.ip4(.{ 127, 0, 0, 1 }, 0)};
    // Both offer at open (glare): the polite side must give way.
    const a = try open(gpa, .{ .polite = true, .bind = &lo }, sides[0].sink());
    defer close(a);
    const b = try open(gpa, .{ .polite = false, .bind = &lo }, sides[1].sink());
    defer close(b);
    try testing.expectEqual(@as(u32, 1), sides[0].offers);
    try testing.expectEqual(@as(u32, 1), sides[1].offers);
    try waitConnected(&sides, .{ a, b }, 5000);
    try testing.expect(sides[0].tracks_video and sides[1].tracks_video);

    // Media both ways; video carries its rotation.
    const key = [_]u8{ 0, 0, 0, 1, 0x67, 0x42, 0xe0, 0x1f, 0, 0, 0, 1, 0x68, 0xce, 0x3c, 0x80, 0, 0, 0, 1, 0x65, 0x88, 0x84 };
    for (0..10) |i| {
        sendAudio(a, &.{ 0xF8, 0xFF, 0xFE });
        sendAudio(b, &.{ 0xF8, 0xFF, 0xFE });
        sendVideo(a, &key, @intCast(i * 3000), 90);
        sleepMs(20);
    }
    sleepMs(400);
    sides[1].spin.lock();
    const got_audio = sides[1].audio;
    const got_video = sides[1].video;
    sides[1].spin.unlock();
    try testing.expect(got_audio >= 9);
    try testing.expect(got_video >= 9);

    // ICE restart from one side: new credentials both ways, still connected afterwards, media flows.
    const old_ufrag = a.pc.iceUfrag()[0..8].*;
    restartIce(a);
    var waited: u32 = 0;
    while (waited < 3000) : (waited += 10) {
        relay(&sides[0], b);
        relay(&sides[1], a);
        sleepMs(10);
        a.driver.lock();
        const done = !std.mem.eql(u8, &old_ufrag, a.pc.iceUfrag()) and a.pc.transport.ice.selected != null and b.pc.transport.ice.selected != null;
        a.driver.unlock();
        if (done) break;
    }
    try testing.expect(waited < 3000);
    try testing.expect(sides[0].isConnected() and sides[1].isConnected());
    sides[1].spin.lock();
    const before = sides[1].audio;
    sides[1].spin.unlock();
    for (0..5) |_| {
        sendAudio(a, &.{ 0xF8, 0xFF, 0xFE });
        sleepMs(20);
    }
    sleepMs(300);
    sides[1].spin.lock();
    defer sides[1].spin.unlock();
    try testing.expect(sides[1].audio >= before + 4);
}

test "polite engine with its own offer out answers a browser's colliding offer" {
    const gpa = testing.allocator;
    var side: Side = .{};
    defer side.deinit();
    const lo = [_]net.Address{net.Address.ip4(.{ 127, 0, 0, 1 }, 0)};
    const p = try open(gpa, .{ .polite = true, .bind = &lo }, side.sink());
    defer close(p);
    const sdp = @import("sdp/sdp.zig");
    const json = try std.json.Stringify.valueAlloc(gpa, .{ .description = .{ .type = "offer", .sdp = sdp.chrome_offer } }, .{});
    defer gpa.free(json);
    signal(p, json);
    const msgs = side.take();
    defer {
        for (msgs) |m| gpa.free(m);
        gpa.free(msgs);
    }
    var answered = false;
    for (msgs) |m| answered = answered or std.mem.indexOf(u8, m, "\"type\":\"answer\"") != null;
    try testing.expect(answered);
}
