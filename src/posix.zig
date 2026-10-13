//! Networking and threads straight on POSIX (BSD sockets, pthreads) for the phones, used by
//! `zui_engine` on Android and iOS instead of std.Io.Threaded:
//!
//! * Zig 0.17's std.Io.Threaded does not compile for iOS (its process-spawning code), and its
//!   cancellation interrupts blocked calls with SIGIO, which kills Android app processes.
//! * The engine needs from an Io only randomness and a clock (keys, certificates, ICE), which
//!   `io()` provides on top of `std.Io.failing`.

const std = @import("std");
const builtin = @import("builtin");
const net = @import("net.zig");
const IceAgent = @import("ice/Agent.zig");
const PeerConnection = @import("peer.zig").PeerConnection;

const c = std.c;

extern "c" fn arc4random_buf(buf: *anyopaque, n: usize) void;

// ---- a minimal std.Io: randomness and clocks ------------------------------------------------

fn random(_: ?*anyopaque, buffer: []u8) void {
    if (buffer.len > 0) arc4random_buf(buffer.ptr, buffer.len);
}

fn randomSecure(_: ?*anyopaque, buffer: []u8) std.Io.RandomSecureError!void {
    if (buffer.len > 0) arc4random_buf(buffer.ptr, buffer.len);
}

fn now(_: ?*anyopaque, clock: std.Io.Clock) std.Io.Timestamp {
    var ts: c.timespec = undefined;
    _ = c.clock_gettime(if (clock == .real) .REALTIME else .MONOTONIC, &ts);
    return .{ .nanoseconds = @as(i96, ts.sec) * std.time.ns_per_s + ts.nsec };
}

const vtable: std.Io.VTable = blk: {
    var v = std.Io.failing.vtable.*;
    v.random = random;
    v.randomSecure = randomSecure;
    v.now = now;
    break :blk v;
};

/// An Io that only gives random bytes and the time: everything PeerConnection needs.
pub fn io() std.Io {
    return .{ .userdata = null, .vtable = &vtable };
}

pub fn nowMs() u64 {
    var ts: c.timespec = undefined;
    _ = c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / std.time.ns_per_ms;
}

pub fn sleepMs(ms: u64) void {
    var ts: c.timespec = .{ .sec = @intCast(ms / 1000), .nsec = @intCast((ms % 1000) * std.time.ns_per_ms) };
    while (c.nanosleep(&ts, &ts) != 0) {}
}

// ---- UDP ------------------------------------------------------------------------------------

fn toSockaddr(a: net.Address) c.sockaddr.in {
    var sa = std.mem.zeroes(c.sockaddr.in);
    sa.family = c.AF.INET;
    sa.port = std.mem.nativeToBig(u16, a.port);
    sa.addr = @bitCast(a.ip[0..4].*);
    return sa;
}

fn fromSockaddr(sa: *const c.sockaddr.in) net.Address {
    return net.Address.ip4(@bitCast(sa.addr), std.mem.bigToNative(u16, sa.port));
}

/// An IPv4 UDP socket.
pub const Udp = struct {
    fd: c.fd_t,
    local: net.Address,

    pub fn open(local: net.Address) !Udp {
        if (local.family != .ip4) return error.AddressFamilyUnsupported;
        const fd = c.socket(c.AF.INET, c.SOCK.DGRAM, 0);
        if (fd < 0) return error.SocketFailed;
        errdefer _ = c.close(fd);
        var sa = toSockaddr(local);
        if (c.bind(fd, @ptrCast(&sa), @sizeOf(c.sockaddr.in)) != 0) return error.BindFailed;
        var bound: c.sockaddr.in = undefined;
        var len: c.socklen_t = @sizeOf(c.sockaddr.in);
        if (c.getsockname(fd, @ptrCast(&bound), &len) != 0) return error.BindFailed;
        var addr = fromSockaddr(&bound);
        if (addr.isUnspecified()) addr.ip = local.ip;
        return .{ .fd = fd, .local = addr };
    }

    pub fn close(u: *Udp) void {
        _ = c.close(u.fd);
    }

    pub fn socket(u: *Udp) net.Socket {
        return .{ .ctx = u, .sendFn = sendFn, .local = u.local };
    }

    fn sendFn(ctx: *anyopaque, to: net.Address, data: []const u8) void {
        const u: *Udp = @ptrCast(@alignCast(ctx));
        u.send(to, data);
    }

    pub fn send(u: *Udp, to: net.Address, data: []const u8) void {
        if (to.family != .ip4) return;
        var sa = toSockaddr(to);
        _ = c.sendto(u.fd, data.ptr, data.len, 0, @ptrCast(&sa), @sizeOf(c.sockaddr.in));
    }

    /// Blocks for one datagram. Null on a transient error.
    pub fn receive(u: *Udp, buf: []u8) ?struct { from: net.Address, data: []u8 } {
        var sa: c.sockaddr.in = undefined;
        var len: c.socklen_t = @sizeOf(c.sockaddr.in);
        const n = c.recvfrom(u.fd, buf.ptr, buf.len, 0, @ptrCast(&sa), &len);
        if (n < 0) return null;
        return .{ .from = fromSockaddr(&sa), .data = buf[0..@intCast(n)] };
    }
};

/// The default route's interface address ("connecting" a UDP socket sends nothing).
pub fn defaultLocalAddress() ?net.Address {
    const fd = c.socket(c.AF.INET, c.SOCK.DGRAM, 0);
    if (fd < 0) return null;
    defer _ = c.close(fd);
    var sa = toSockaddr(net.Address.ip4(.{ 8, 8, 8, 8 }, 53));
    if (c.connect(fd, @ptrCast(&sa), @sizeOf(c.sockaddr.in)) != 0) return null;
    var bound: c.sockaddr.in = undefined;
    var len: c.socklen_t = @sizeOf(c.sockaddr.in);
    if (c.getsockname(fd, @ptrCast(&bound), &len) != 0) return null;
    var a = fromSockaddr(&bound);
    if (a.isUnspecified()) return null;
    a.port = 0;
    return a;
}

/// An IPv4 literal or a host name (getaddrinfo).
pub fn resolve(host: []const u8, port: u16) !net.Address {
    if (net.Address.parseIp(host, port)) |a| return a else |_| {}
    var name: [256]u8 = undefined;
    if (host.len >= name.len) return error.NameTooLong;
    @memcpy(name[0..host.len], host);
    name[host.len] = 0;
    var hints = std.mem.zeroes(c.addrinfo);
    hints.family = c.AF.INET;
    hints.socktype = c.SOCK.DGRAM;
    var res: ?*c.addrinfo = null;
    if (@backingInt(c.getaddrinfo(name[0..host.len :0], null, &hints, &res)) != 0) return error.UnknownHostName;
    defer c.freeaddrinfo(res.?);
    var it = res;
    while (it) |ai| : (it = ai.next) {
        if (ai.family == c.AF.INET) if (ai.addr) |sa| {
            var a = fromSockaddr(@ptrCast(@alignCast(sa)));
            a.port = port;
            return a;
        };
    }
    return error.UnknownHostName;
}

/// Like `driver.Driver`, on threads: a receive thread per socket and a timer thread around one
/// PeerConnection. Other callers hold `lock` while they use it.
pub const Driver = struct {
    pc: *PeerConnection,
    sockets: []Udp,
    /// TURN stream connections; they are the PeerConnection's sockets after the UDP ones.
    streams: []*StreamConn = &.{},
    mutex: Mutex = .{},
    /// pthreads directly: std.Thread's error path reaches std.debug, whose default Io does not
    /// compile for iOS.
    threads: [8]?c.pthread_t = @splat(null),
    contexts: [8]Ctx = undefined,
    stopping: std.atomic.Value(bool) = .init(false),
    on_tick: ?struct { ctx: *anyopaque, f: *const fn (ctx: *anyopaque) void } = null,

    const Mutex = struct {
        m: c.pthread_mutex_t = .{},
        fn lock(x: *Mutex) void {
            _ = c.pthread_mutex_lock(&x.m);
        }
        fn unlock(x: *Mutex) void {
            _ = c.pthread_mutex_unlock(&x.m);
        }
    };

    const Ctx = struct { d: *Driver, index: u8 };

    fn spawn(d: *Driver, slot: usize, f: *const fn (?*anyopaque) callconv(.c) ?*anyopaque) !void {
        d.contexts[slot] = .{ .d = d, .index = @intCast(slot) };
        var t: c.pthread_t = undefined;
        if (c.pthread_create(&t, null, f, &d.contexts[slot]) != .SUCCESS) return error.ThreadFailed;
        d.threads[slot] = t;
    }

    fn receiveEntry(arg: ?*anyopaque) callconv(.c) ?*anyopaque {
        const x: *Ctx = @ptrCast(@alignCast(arg.?));
        receiveLoop(x.d, x.index);
        return null;
    }

    fn streamEntry(arg: ?*anyopaque) callconv(.c) ?*anyopaque {
        const x: *Ctx = @ptrCast(@alignCast(arg.?));
        x.d.streams[x.index - x.d.sockets.len].run(x, deliverStream);
        return null;
    }

    fn deliverStream(ctx: *anyopaque, msg: []const u8) void {
        const x: *Ctx = @ptrCast(@alignCast(ctx));
        const d = x.d;
        if (d.stopping.load(.acquire)) return;
        d.mutex.lock();
        defer d.mutex.unlock();
        d.pc.receive(x.index, d.streams[x.index - d.sockets.len].server, msg, nowMs());
        if (d.on_tick) |h| h.f(h.ctx);
    }

    fn timerEntry(arg: ?*anyopaque) callconv(.c) ?*anyopaque {
        const x: *Ctx = @ptrCast(@alignCast(arg.?));
        timerLoop(x.d);
        return null;
    }

    pub fn init(pc: *PeerConnection, sockets: []Udp) Driver {
        return .{ .pc = pc, .sockets = sockets };
    }

    pub fn start(d: *Driver) !void {
        if (d.sockets.len + d.streams.len > d.threads.len - 1) return error.TooManySockets;
        for (0..d.sockets.len) |i| try d.spawn(i, receiveEntry);
        for (0..d.streams.len) |i| try d.spawn(d.sockets.len + i, streamEntry);
        try d.spawn(d.threads.len - 1, timerEntry);
    }

    /// Stops and joins the threads: a flag, and a datagram to each socket to wake its receive.
    pub fn stop(d: *Driver) void {
        d.stopping.store(true, .release);
        for (d.sockets) |*u| {
            var to = u.local;
            if (to.isUnspecified()) to = net.Address.ip4(.{ 127, 0, 0, 1 }, to.port);
            u.send(to, &.{0});
        }
        for (d.streams) |sc| sc.close();
        for (&d.threads) |*t| if (t.*) |th| {
            _ = c.pthread_join(th, null);
            t.* = null;
        };
    }

    pub fn lock(d: *Driver) void {
        d.mutex.lock();
    }

    pub fn unlock(d: *Driver) void {
        d.mutex.unlock();
    }

    fn receiveLoop(d: *Driver, index: u8) void {
        var buf: [2048]u8 = undefined;
        while (!d.stopping.load(.acquire)) {
            const msg = d.sockets[index].receive(&buf) orelse continue;
            if (d.stopping.load(.acquire)) return;
            d.mutex.lock();
            defer d.mutex.unlock();
            d.pc.receive(index, msg.from, msg.data, nowMs());
            if (d.on_tick) |h| h.f(h.ctx);
        }
    }

    fn timerLoop(d: *Driver) void {
        while (!d.stopping.load(.acquire)) {
            var wait_ms: u64 = 20;
            {
                d.mutex.lock();
                defer d.mutex.unlock();
                const t = nowMs();
                d.pc.poll(t);
                if (d.on_tick) |h| h.f(h.ctx);
                if (d.pc.nextTimeout()) |next| wait_ms = std.math.clamp(next -| t, 1, 20);
            }
            sleepMs(wait_ms);
        }
    }
};

/// iceServers urls to servers, resolved with getaddrinfo: stun:, turn: (UDP),
/// turn:...?transport=tcp (TCP) and turns: (TLS, port 5349 unless given).
pub fn resolveIceServers(gpa: std.mem.Allocator, list: []const @import("driver.zig").IceServerUrls) ![]IceAgent.Server {
    var out: std.ArrayList(IceAgent.Server) = .empty;
    errdefer @import("driver.zig").freeServers(gpa, out.items);
    for (list) |entry| for (entry.urls) |url| {
        const tls = std.mem.startsWith(u8, url, "turns:");
        const turn = tls or std.mem.startsWith(u8, url, "turn:");
        if (!turn and !std.mem.startsWith(u8, url, "stun:")) continue;
        var rest = url[if (tls) 6 else 5..];
        var transport: IceAgent.Server.Transport = if (tls) .tls else .udp;
        if (std.mem.indexOfScalar(u8, rest, '?')) |q| {
            if (!tls and std.mem.indexOf(u8, rest[q..], "transport=tcp") != null) transport = .tcp;
            rest = rest[0..q];
        }
        var host = rest;
        var port: u16 = if (tls) 5349 else 3478;
        if (std.mem.lastIndexOfScalar(u8, rest, ':')) |i| {
            host = rest[0..i];
            port = std.fmt.parseInt(u16, rest[i + 1 ..], 10) catch 3478;
        }
        const address = resolve(host, port) catch continue;
        const user = try gpa.dupe(u8, if (turn) entry.username else "");
        errdefer gpa.free(user);
        const pass = try gpa.dupe(u8, if (turn) entry.credential else "");
        errdefer gpa.free(pass);
        const name = try gpa.dupe(u8, host);
        errdefer gpa.free(name);
        try out.append(gpa, .{ .address = address, .turn = turn, .username = user, .password = pass, .transport = transport, .host = name });
    };
    return out.toOwnedSlice(gpa);
}

// ---- TURN over TCP and TLS ------------------------------------------------------------------

/// A stream connection to one TURN server (TCP, or TLS for "turns:"), used as a `net.Socket`
/// with `remote` set. It connects on its own thread (opening a call never blocks on it); what
/// is sent before then waits. Received data is cut into whole TURN messages (STUN by its header
/// length, ChannelData by its length padded to 4, RFC 8656 §12.5).
///
/// TLS: std's client, with the server name sent (SNI) but the certificate chain not checked
/// against a CA store: on the phones std has no store it can use without std.Io.Threaded. The
/// calls stay safe: media is end-to-end DTLS-SRTP pinned by the SDP fingerprints, and TURN
/// requests are authenticated with HMAC; what is exposed is metadata to whoever intercepts
/// the TURN connection.
pub const StreamConn = struct {
    const tls = std.crypto.tls;

    gpa: std.mem.Allocator,
    server: net.Address,
    host: []u8,
    use_tls: bool,
    fd: c.fd_t = -1,
    state: std.atomic.Value(State) = .init(.connecting),
    write_lock: Mutex = .{},
    pending: std.ArrayList(u8) = .empty,

    raw_reader: std.Io.Reader = undefined,
    raw_writer: std.Io.Writer = undefined,
    raw_read_buf: [tls.Client.min_buffer_len]u8 = undefined,
    raw_write_buf: [tls.Client.min_buffer_len]u8 = undefined,
    client: tls.Client = undefined,
    tls_read_buf: [tls.Client.min_buffer_len]u8 = undefined,
    tls_write_buf: [tls.Client.min_buffer_len]u8 = undefined,

    pub const State = enum(u8) { connecting, open, failed, closed };

    const Mutex = struct {
        m: c.pthread_mutex_t = .{},
        fn lock(x: *Mutex) void {
            _ = c.pthread_mutex_lock(&x.m);
        }
        fn unlock(x: *Mutex) void {
            _ = c.pthread_mutex_unlock(&x.m);
        }
    };

    pub fn create(gpa: std.mem.Allocator, server: net.Address, host: []const u8, use_tls: bool) !*StreamConn {
        const sc = try gpa.create(StreamConn);
        errdefer gpa.destroy(sc);
        sc.* = .{ .gpa = gpa, .server = server, .host = try gpa.dupe(u8, host), .use_tls = use_tls };
        return sc;
    }

    pub fn destroy(sc: *StreamConn) void {
        if (sc.fd >= 0) _ = c.close(sc.fd);
        sc.pending.deinit(sc.gpa);
        sc.gpa.free(sc.host);
        sc.gpa.destroy(sc);
    }

    pub fn socket(sc: *StreamConn) net.Socket {
        return .{ .ctx = sc, .sendFn = sendFn, .local = net.Address.ip4(.{ 0, 0, 0, 0 }, 0), .remote = sc.server };
    }

    /// Unblocks `run` (from another thread) so it returns.
    pub fn close(sc: *StreamConn) void {
        sc.state.store(.closed, .release);
        if (sc.fd >= 0) _ = c.shutdown(sc.fd, 2);
    }

    fn sendFn(ctx: *anyopaque, _: net.Address, data: []const u8) void {
        const sc: *StreamConn = @ptrCast(@alignCast(ctx));
        sc.write_lock.lock();
        defer sc.write_lock.unlock();
        switch (sc.state.load(.acquire)) {
            .open => sc.writeOut(data) catch sc.close(),
            .connecting => if (sc.pending.items.len + data.len <= 64 * 1024) {
                sc.pending.appendSlice(sc.gpa, data) catch {};
            },
            .failed, .closed => {},
        }
    }

    fn writeOut(sc: *StreamConn, data: []const u8) !void {
        if (sc.use_tls) {
            try sc.client.writer.writeAll(data);
            try sc.client.writer.flush();
        } else {
            try sc.raw_writer.writeAll(data);
        }
        try sc.raw_writer.flush();
    }

    fn fdStream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const sc: *StreamConn = @alignCast(@fieldParentPtr("raw_reader", r));
        const dest = limit.slice(try w.writableSliceGreedy(1));
        const n = c.read(sc.fd, dest.ptr, dest.len);
        if (n < 0) return error.ReadFailed;
        if (n == 0) return error.EndOfStream;
        w.advance(@intCast(n));
        return @intCast(n);
    }

    fn fdWrite(fd: c.fd_t, data: []const u8) std.Io.Writer.Error!void {
        var rest = data;
        while (rest.len > 0) {
            const n = c.write(fd, rest.ptr, rest.len);
            if (n <= 0) return error.WriteFailed;
            rest = rest[@intCast(n)..];
        }
    }

    fn fdDrain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const sc: *StreamConn = @alignCast(@fieldParentPtr("raw_writer", w));
        try fdWrite(sc.fd, w.buffered());
        w.end = 0;
        var n: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            try fdWrite(sc.fd, d);
            n += d.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| try fdWrite(sc.fd, last);
        return n + last.len * splat;
    }

    fn connect(sc: *StreamConn) !void {
        const fd = c.socket(c.AF.INET, c.SOCK.STREAM, 0);
        if (fd < 0) return error.SocketFailed;
        sc.fd = fd;
        var sa = toSockaddr(sc.server);
        if (c.connect(fd, @ptrCast(&sa), @sizeOf(c.sockaddr.in)) != 0) return error.ConnectFailed;
        sc.raw_reader = .{ .vtable = &.{ .stream = fdStream }, .buffer = &sc.raw_read_buf, .seek = 0, .end = 0 };
        sc.raw_writer = .{ .vtable = &.{ .drain = fdDrain }, .buffer = &sc.raw_write_buf };
        if (!sc.use_tls) return;
        var entropy: [tls.Client.Options.entropy_len]u8 = undefined;
        arc4random_buf(&entropy, entropy.len);
        sc.client = try tls.Client.init(&sc.raw_reader, &sc.raw_writer, .{
            .host = if (sc.host.len > 0) .{ .explicit = sc.host } else .no_verification,
            .ca = .no_verification,
            .read_buffer = &sc.tls_read_buf,
            .write_buffer = &sc.tls_write_buf,
            .entropy = &entropy,
            .realtime_now = now(null, .real),
        });
    }

    /// Connects, then hands every received TURN message to `deliver` until closed. Runs on
    /// the connection's own thread.
    pub fn run(sc: *StreamConn, ctx: *anyopaque, deliver: *const fn (ctx: *anyopaque, msg: []const u8) void) void {
        sc.connect() catch {
            sc.state.store(.failed, .release);
            return;
        };
        {
            sc.write_lock.lock();
            defer sc.write_lock.unlock();
            if (sc.state.load(.acquire) == .closed) return;
            sc.state.store(.open, .release);
            if (sc.pending.items.len > 0) sc.writeOut(sc.pending.items) catch {};
            sc.pending.clearRetainingCapacity();
        }
        const src: *std.Io.Reader = if (sc.use_tls) &sc.client.reader else &sc.raw_reader;
        var msg: [4 + 65535 + 3]u8 = undefined;
        while (sc.state.load(.acquire) == .open) {
            src.readSliceAll(msg[0..4]) catch break;
            const len = std.mem.readInt(u16, msg[2..4], .big);
            const total: usize = switch (msg[0] >> 6) {
                0 => 20 + @as(usize, len), // STUN: 20-byte header, length excludes it
                1 => 4 + std.mem.alignForward(usize, len, 4), // ChannelData, padded over streams
                else => break, // not TURN: the stream is out of step
            };
            src.readSliceAll(msg[4..total]) catch break;
            deliver(ctx, msg[0..total]);
        }
        if (sc.state.load(.acquire) != .closed) sc.state.store(.failed, .release);
    }
};
