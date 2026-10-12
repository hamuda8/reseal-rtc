//! ICE + DTLS over one UDP association, demultiplexed by the first byte (RFC 7983):
//! 0..3 STUN (handled inside the ICE agent), 20..63 DTLS, 128..191 RTP/RTCP (handed to
//! whoever registered as the media sink). The transport knows nothing about media.
//!
//! Must live at a stable address (its callbacks point at it): use `init` in place.

const std = @import("std");
const PeerTransport = @This();

const IceAgent = @import("../ice/Agent.zig");
const DtlsConn = @import("../dtls/Conn.zig");
const certs = @import("../dtls/cert.zig");
const net = @import("../net.zig");
const Profile = @import("../media/srtp.zig").Profile;

pub const State = enum { new, connecting, connected, failed, closed };

pub const Events = struct {
    ctx: *anyopaque,
    candidate: *const fn (ctx: *anyopaque, c: *const IceAgent.Candidate) void,
    gathering_done: *const fn (ctx: *anyopaque) void,
    ice_state: *const fn (ctx: *anyopaque, s: IceAgent.State) void,
    /// DTLS finished and the peer's fingerprint matched: SRTP keys can be exported.
    secure: *const fn (ctx: *anyopaque) void,
    state: *const fn (ctx: *anyopaque, s: State) void,
    /// SRTP or SRTCP datagram (still protected). The slice is only valid during the call.
    media: *const fn (ctx: *anyopaque, data: []const u8) void,
    /// DTLS application data (SCTP, for data channels later).
    data: ?*const fn (ctx: *anyopaque, data: []const u8) void = null,
};

pub const Config = struct {
    ice: IceAgent.Config,
    certificate: *const certs.Certificate,
    srtp_profiles: []const Profile = &.{ .aead_aes128_gcm, .aes128_cm_sha1_80 },
};

gpa: std.mem.Allocator,
io: std.Io,
config: Config,
events: Events,
ice: IceAgent,
dtls: ?DtlsConn = null,
remote_fingerprint: ?certs.Fingerprint = null,
state: State = .new,
now: u64 = 0,

pub fn init(t: *PeerTransport, gpa: std.mem.Allocator, io: std.Io, config: Config, sockets: []const net.Socket, events: Events) !void {
    t.* = .{ .gpa = gpa, .io = io, .config = config, .events = events, .ice = undefined };
    t.ice = try IceAgent.init(gpa, io, config.ice, sockets, .{
        .ctx = t,
        .candidate = onCandidate,
        .gathering_done = onGatheringDone,
        .state = onIceState,
    });
}

pub fn deinit(t: *PeerTransport) void {
    if (t.dtls) |*d| d.deinit();
    t.ice.deinit();
}

fn setState(t: *PeerTransport, s: State) void {
    if (t.state == s) return;
    t.state = s;
    t.events.state(t.events.ctx, s);
}

fn onCandidate(ctx: *anyopaque, c: *const IceAgent.Candidate) void {
    const t: *PeerTransport = @ptrCast(@alignCast(ctx));
    t.events.candidate(t.events.ctx, c);
}

fn onGatheringDone(ctx: *anyopaque) void {
    const t: *PeerTransport = @ptrCast(@alignCast(ctx));
    t.events.gathering_done(t.events.ctx);
}

fn onIceState(ctx: *anyopaque, s: IceAgent.State) void {
    const t: *PeerTransport = @ptrCast(@alignCast(ctx));
    t.events.ice_state(t.events.ctx, s);
    switch (s) {
        .checking => t.setState(.connecting),
        .connected => t.maybeStartDtls(),
        .failed => t.setState(.failed),
        else => {},
    }
}

/// Decides the DTLS role (from a=setup) once known. The client starts as soon as ICE has a
/// pair; the server waits for the ClientHello.
pub fn setDtlsRole(t: *PeerTransport, role: DtlsConn.Role) void {
    if (t.dtls != null) return;
    t.dtls = DtlsConn.init(t.gpa, t.io, .{
        .role = role,
        .certificate = t.config.certificate,
        .srtp_profiles = t.config.srtp_profiles,
        .remote_fingerprint = t.remote_fingerprint,
    }, .{ .ctx = t, .send = dtlsSend, .data = dtlsData });
    t.maybeStartDtls();
}

pub fn setRemoteFingerprint(t: *PeerTransport, fp: certs.Fingerprint) void {
    t.remote_fingerprint = fp;
    if (t.dtls) |*d| {
        d.setRemoteFingerprint(fp);
        t.afterDtls();
    }
}

fn maybeStartDtls(t: *PeerTransport) void {
    const d = &(t.dtls orelse return);
    if (d.state == .new and d.isClient() and t.ice.selected != null) d.start(t.now);
}

fn dtlsSend(ctx: *anyopaque, datagram: []const u8) void {
    const t: *PeerTransport = @ptrCast(@alignCast(ctx));
    t.ice.send(datagram) catch {};
}

fn dtlsData(ctx: *anyopaque, data: []const u8) void {
    const t: *PeerTransport = @ptrCast(@alignCast(ctx));
    if (t.events.data) |f| f(t.events.ctx, data);
}

fn afterDtls(t: *PeerTransport) void {
    const d = &(t.dtls orelse return);
    switch (d.state) {
        .connected => if (t.state != .connected) {
            t.setState(.connected);
            t.events.secure(t.events.ctx);
        },
        .failed => t.setState(.failed),
        .closed => t.setState(.closed),
        else => {},
    }
}

/// A datagram from `sockets[socket]`.
pub fn receive(t: *PeerTransport, socket: u8, from: net.Address, data: []const u8, now: u64) void {
    t.now = now;
    const app = t.ice.receive(socket, from, data, now) orelse return;
    if (app.len == 0) return;
    switch (app[0]) {
        20...63 => if (t.dtls) |*d| {
            d.handle(app, now);
            t.afterDtls();
        },
        128...191 => if (t.state == .connected) t.events.media(t.events.ctx, app),
        else => {},
    }
}

pub fn poll(t: *PeerTransport, now: u64) void {
    t.now = now;
    t.ice.poll(now);
    if (t.dtls) |*d| {
        t.maybeStartDtls();
        d.poll(now);
        t.afterDtls();
    }
}

pub fn nextTimeout(t: *const PeerTransport) ?u64 {
    var next = t.ice.nextTimeout();
    if (t.dtls) |*d| if (d.nextTimeout()) |v| {
        next = if (next) |n| @min(n, v) else v;
    };
    return next;
}

/// Sends a protected media datagram (SRTP/SRTCP) on the selected pair.
pub fn sendMedia(t: *PeerTransport, data: []const u8) void {
    if (t.state != .connected) return;
    t.ice.send(data) catch {};
}

pub fn srtpProfile(t: *const PeerTransport) ?Profile {
    const d = &(t.dtls orelse return null);
    return d.srtp_profile;
}

pub fn isDtlsClient(t: *const PeerTransport) bool {
    const d = &(t.dtls orelse return false);
    return d.isClient();
}

pub fn exportSrtpKeys(t: *const PeerTransport, out: []u8) !void {
    const d = &(t.dtls orelse return error.NotConnected);
    try d.exportKeyingMaterial(out, "EXTRACTOR-dtls_srtp");
}

pub fn close(t: *PeerTransport) void {
    if (t.dtls) |*d| d.close();
    t.ice.close();
    t.setState(.closed);
}
