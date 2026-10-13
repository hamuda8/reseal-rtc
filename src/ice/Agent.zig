//! ICE agent (RFC 8445) for one data stream with one component (BUNDLE + rtcp-mux, as every
//! browser negotiates): gathers host, server-reflexive (STUN) and relayed (TURN) candidates,
//! pairs them with trickled remote candidates, runs paced connectivity checks, learns
//! peer-reflexive candidates, nominates (regular nomination when controlling, USE-CANDIDATE
//! when controlled) and keeps consent fresh (RFC 7675).
//!
//! Simplifications, all compatible with browsers: every pair starts Waiting (no frozen
//! foundations: one stream, one component), server-reflexive candidates are signalled but not
//! paired (their base is the host candidate, RFC 8445 6.1.2.4), and mDNS ".local" remote
//! candidates are ignored in favour of the peer-reflexive candidate their checks reveal.

const std = @import("std");
const Agent = @This();

const stun = @import("stun.zig");
const cand = @import("candidate.zig");
const TurnClient = @import("turn.zig");
const net = @import("../net.zig");
const Address = net.Address;
const Socket = net.Socket;

pub const Candidate = cand.Candidate;

pub const Role = enum { controlling, controlled };

pub const State = enum { new, checking, connected, disconnected, failed, closed };

/// A STUN or TURN server, already resolved to an address.
pub const Server = struct {
    address: Address,
    turn: bool = false,
    username: []const u8 = "",
    password: []const u8 = "",
};

pub const Config = struct {
    role: Role,
    servers: []const Server = &.{},
    /// Pacing between new checks (Ta).
    check_interval_ms: u64 = 50,
    /// Controlling side: how long to wait after the first valid pair for better ones.
    nomination_delay_ms: u64 = 200,
    consent_interval_ms: u64 = 5000,
    disconnected_after_ms: u64 = 10_000,
    failed_after_ms: u64 = 30_000,
};

pub const Callbacks = struct {
    ctx: *anyopaque,
    /// A new local candidate to signal to the peer (trickle ICE).
    candidate: *const fn (ctx: *anyopaque, c: *const Candidate) void,
    gathering_done: *const fn (ctx: *anyopaque) void,
    state: *const fn (ctx: *anyopaque, s: State) void,
};

const Base = struct {
    socket: u8,
    turn: ?u8 = null,

    fn eql(a: Base, b: Base) bool {
        return a.socket == b.socket and a.turn == b.turn;
    }
};

const Local = struct {
    c: Candidate,
    base: Base,
    pairable: bool, // host and relay; srflx is only signalled
};

pub const PairState = enum { waiting, in_progress, succeeded, failed };

pub const Pair = struct {
    local: u16,
    remote: u16,
    priority: u64,
    state: PairState = .waiting,
    nominated: bool = false,
    use_candidate_seen: bool = false,
    last_response: u64 = 0,
    next_consent: u64 = 0,
};

const Check = struct {
    txid: [12]u8,
    pair: u16,
    use_candidate: bool,
    next_at: u64,
    rto: u64,
    attempts: u8,
    msg: [256]u8 = undefined,
    len: usize = 0,
};

const Gather = struct {
    txid: [12]u8,
    socket: u8,
    server: Address,
    next_at: u64,
    attempts: u8,
    done: bool = false,
};

const max_check_attempts = 7;

gpa: std.mem.Allocator,
io: std.Io,
config: Config,
cb: Callbacks,
sockets: []Socket,

role: Role,
tiebreaker: u64,
local_ufrag: [8]u8,
local_pwd: [24]u8,
remote_ufrag: std.ArrayList(u8) = .empty,
remote_pwd: std.ArrayList(u8) = .empty,

locals: std.ArrayList(Local) = .empty,
remotes: std.ArrayList(Candidate) = .empty,
pairs: std.ArrayList(Pair) = .empty,
checks: std.ArrayList(Check) = .empty,
triggered: std.ArrayList(u16) = .empty,
gathers: std.ArrayList(Gather) = .empty,
turns: std.ArrayList(TurnClient) = .empty,
turn_settled: std.ArrayList(bool) = .empty,

state: State = .new,
gathering_started: bool = false,
gathering_complete: bool = false,
selected: ?u16 = null,
nominating: bool = false,
first_valid_at: ?u64 = null,
checking_since: u64 = 0,
next_check_at: u64 = 0,
now: u64 = 0,
/// The previous path during an ICE restart: media keeps flowing on it until a new pair is selected.
fallback: ?struct { base: Base, to: Address } = null,

pub fn init(gpa: std.mem.Allocator, io: std.Io, config: Config, sockets: []const Socket, cb: Callbacks) !Agent {
    var a: Agent = .{
        .gpa = gpa,
        .io = io,
        .config = config,
        .cb = cb,
        .sockets = try gpa.dupe(Socket, sockets),
        .role = config.role,
        .tiebreaker = undefined,
        .local_ufrag = undefined,
        .local_pwd = undefined,
    };
    io.random(std.mem.asBytes(&a.tiebreaker));
    randomIceChars(io, &a.local_ufrag);
    randomIceChars(io, &a.local_pwd);
    return a;
}

pub fn deinit(a: *Agent) void {
    for (a.turns.items) |*t| t.deinit();
    a.turns.deinit(a.gpa);
    a.turn_settled.deinit(a.gpa);
    a.gpa.free(a.sockets);
    a.remote_ufrag.deinit(a.gpa);
    a.remote_pwd.deinit(a.gpa);
    a.locals.deinit(a.gpa);
    a.remotes.deinit(a.gpa);
    a.pairs.deinit(a.gpa);
    a.checks.deinit(a.gpa);
    a.triggered.deinit(a.gpa);
    a.gathers.deinit(a.gpa);
}

fn randomIceChars(io: std.Io, out: []u8) void {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    io.random(out);
    for (out) |*b| b.* = alphabet[b.* & 63];
}

fn setState(a: *Agent, s: State) void {
    if (a.state == s) return;
    a.state = s;
    a.cb.state(a.cb.ctx, s);
}

pub fn hasRemoteCredentials(a: *const Agent) bool {
    return a.remote_ufrag.items.len > 0;
}

/// From the remote description (a=ice-ufrag / a=ice-pwd).
pub fn setRemoteCredentials(a: *Agent, ufrag: []const u8, pwd: []const u8) !void {
    a.remote_ufrag.clearRetainingCapacity();
    try a.remote_ufrag.appendSlice(a.gpa, ufrag);
    a.remote_pwd.clearRetainingCapacity();
    try a.remote_pwd.appendSlice(a.gpa, pwd);
    a.startChecking();
}

/// True when the remote description carries credentials other than the ones in use: the peer
/// restarted ICE.
pub fn remoteCredentialsChanged(a: *const Agent, ufrag: []const u8, pwd: []const u8) bool {
    if (!a.hasRemoteCredentials()) return false;
    return !std.mem.eql(u8, a.remote_ufrag.items, ufrag) or !std.mem.eql(u8, a.remote_pwd.items, pwd);
}

/// ICE restart (RFC 8445 9): new local credentials, the remote side's candidates and every pair
/// forgotten, and our candidates signalled again for the new generation. Gathered candidates and
/// TURN allocations are kept. Until a new pair is selected, sending uses the old path.
pub fn restart(a: *Agent) void {
    if (a.selected) |s| {
        const p = a.pairs.items[s];
        a.fallback = .{ .base = a.locals.items[p.local].base, .to = a.remotes.items[p.remote].address };
    }
    randomIceChars(a.io, &a.local_ufrag);
    randomIceChars(a.io, &a.local_pwd);
    a.remote_ufrag.clearRetainingCapacity();
    a.remote_pwd.clearRetainingCapacity();
    a.remotes.clearRetainingCapacity();
    a.pairs.clearRetainingCapacity();
    a.checks.clearRetainingCapacity();
    a.triggered.clearRetainingCapacity();
    a.selected = null;
    a.nominating = false;
    a.first_valid_at = null;
    // Quietly back to new: the owner sees "checking" once the new credentials arrive.
    if (a.state != .closed) a.state = .new;
    for (a.locals.items) |*l| a.cb.candidate(a.cb.ctx, &l.c);
}

fn startChecking(a: *Agent) void {
    if (a.state == .new and a.hasRemoteCredentials() and a.pairs.items.len > 0) {
        a.checking_since = a.now;
        a.setState(.checking);
    }
}

// ---- gathering ----------------------------------------------------------------------------

/// Emits host candidates and starts STUN and TURN gathering.
pub fn gather(a: *Agent, now: u64) !void {
    a.now = now;
    if (a.gathering_started) return;
    a.gathering_started = true;
    for (a.sockets, 0..) |s, i| {
        if (s.local.isUnspecified()) continue;
        try a.addLocal(.host, s.local, null, .{ .socket = @intCast(i) }, true, @intCast(1000 + i));
    }
    for (a.config.servers) |srv| {
        for (a.sockets, 0..) |s, i| {
            if (s.local.family != srv.address.family) continue;
            if (srv.turn) {
                const out: TurnClient.Output = .{ .ctx = a, .send = turnSend };
                var t = try TurnClient.init(a.gpa, a.io, out, @intCast(i), srv.address, srv.username, srv.password);
                errdefer t.deinit();
                try a.turns.append(a.gpa, t);
                try a.turn_settled.append(a.gpa, false);
                a.turns.items[a.turns.items.len - 1].start(now);
            } else {
                var g: Gather = .{ .txid = undefined, .socket = @intCast(i), .server = srv.address, .next_at = now + 300, .attempts = 1 };
                a.io.random(&g.txid);
                try a.gathers.append(a.gpa, g);
                a.sendGather(&g);
            }
        }
    }
    a.checkGatheringDone();
}

fn turnSend(ctx: *anyopaque, socket: u8, to: Address, data: []const u8) void {
    const a: *Agent = @ptrCast(@alignCast(ctx));
    a.sockets[socket].send(to, data);
}

fn sendGather(a: *Agent, g: *const Gather) void {
    var buf: [64]u8 = undefined;
    var b = stun.Builder.init(&buf, .binding, .request, g.txid);
    b.addFingerprint() catch return;
    a.sockets[g.socket].send(g.server, b.bytes());
}

fn checkGatheringDone(a: *Agent) void {
    if (a.gathering_complete) return;
    for (a.gathers.items) |g| if (!g.done) return;
    for (a.turn_settled.items) |s| if (!s) return;
    a.gathering_complete = true;
    a.cb.gathering_done(a.cb.ctx);
}

fn addLocal(a: *Agent, t: cand.Type, addr: Address, related: ?Address, base: Base, pairable: bool, foundation: u32) !void {
    for (a.locals.items) |l| if (l.c.type == t and l.c.address.eql(addr)) return;
    const local_pref: u16 = 65535 - @as(u16, base.socket) * 64 - (if (base.turn) |x| @as(u16, x) else 0);
    var c: Candidate = .{ .priority = cand.priority(t, local_pref, 1), .address = addr, .type = t, .related = related };
    var fbuf: [16]u8 = undefined;
    c.setFoundation(std.fmt.bufPrint(&fbuf, "{d}", .{foundation}) catch unreachable);
    try a.locals.append(a.gpa, .{ .c = c, .base = base, .pairable = pairable });
    const li: u16 = @intCast(a.locals.items.len - 1);
    if (pairable) for (0..a.remotes.items.len) |ri| try a.addPair(li, @intCast(ri));
    a.cb.candidate(a.cb.ctx, &a.locals.items[li].c);
}

pub fn localCandidates(a: *const Agent) []const Local {
    return a.locals.items;
}

// ---- remote candidates and pairs ----------------------------------------------------------

/// Adds a trickled or SDP candidate. Unresolvable (mDNS) and duplicate candidates are ignored.
pub fn addRemoteCandidate(a: *Agent, c: Candidate) !void {
    if (c.unresolved or c.component != 1) return;
    _ = try a.findOrAddRemote(c);
    a.startChecking();
}

fn findOrAddRemote(a: *Agent, c: Candidate) !u16 {
    for (a.remotes.items, 0..) |r, i| if (r.address.eql(c.address)) return @intCast(i);
    try a.remotes.append(a.gpa, c);
    const ri: u16 = @intCast(a.remotes.items.len - 1);
    for (a.locals.items, 0..) |l, li| if (l.pairable) try a.addPair(@intCast(li), ri);
    return ri;
}

fn addPair(a: *Agent, li: u16, ri: u16) !void {
    const l = a.locals.items[li];
    const r = a.remotes.items[ri];
    if (l.c.address.family != r.address.family) return;
    for (a.pairs.items) |p| if (p.local == li and p.remote == ri) return;
    try a.pairs.append(a.gpa, .{ .local = li, .remote = ri, .priority = a.pairPriority(li, ri) });
    if (l.base.turn) |t| a.turns.items[t].permit(r.address);
}

fn pairPriority(a: *const Agent, li: u16, ri: u16) u64 {
    const lp = a.locals.items[li].c.priority;
    const rp = a.remotes.items[ri].priority;
    return if (a.role == .controlling) cand.pairPriority(lp, rp) else cand.pairPriority(rp, lp);
}

fn findPair(a: *const Agent, li: u16, ri: u16) ?u16 {
    for (a.pairs.items, 0..) |p, i| if (p.local == li and p.remote == ri) return @intCast(i);
    return null;
}

fn localForBase(a: *const Agent, base: Base) ?u16 {
    for (a.locals.items, 0..) |l, i| if (l.pairable and l.base.eql(base)) return @intCast(i);
    return null;
}

/// Offerer controls, answerer is controlled (RFC 8445 6.1.1); set before checks start.
pub fn setRole(a: *Agent, role: Role) void {
    a.switchRole(role);
}

fn switchRole(a: *Agent, role: Role) void {
    a.role = role;
    for (a.pairs.items) |*p| p.priority = a.pairPriority(p.local, p.remote);
}

// ---- sending ------------------------------------------------------------------------------

fn sendFrom(a: *Agent, base: Base, to: Address, data: []const u8) void {
    if (base.turn) |t| {
        a.turns.items[t].send(to, data);
    } else {
        a.sockets[base.socket].send(to, data);
    }
}

/// Sends application data (DTLS, SRTP) on the selected pair.
pub fn send(a: *Agent, data: []const u8) !void {
    const pi = a.selected orelse {
        const f = a.fallback orelse return error.NotConnected;
        return a.sendFrom(f.base, f.to, data);
    };
    const p = a.pairs.items[pi];
    a.sendFrom(a.locals.items[p.local].base, a.remotes.items[p.remote].address, data);
}

pub fn selectedPair(a: *const Agent) ?struct { local: Candidate, remote: Candidate } {
    const pi = a.selected orelse return null;
    const p = a.pairs.items[pi];
    return .{ .local = a.locals.items[p.local].c, .remote = a.remotes.items[p.remote] };
}

fn startCheck(a: *Agent, pi: u16, use_candidate: bool) void {
    if (!a.hasRemoteCredentials()) return;
    const p = &a.pairs.items[pi];
    const l = a.locals.items[p.local];
    var ck: Check = .{ .txid = undefined, .pair = pi, .use_candidate = use_candidate, .next_at = a.now + 200, .rto = 200, .attempts = 1 };
    a.io.random(&ck.txid);
    var b = stun.Builder.init(&ck.msg, .binding, .request, ck.txid);
    var user_buf: [600]u8 = undefined;
    const user = std.fmt.bufPrint(&user_buf, "{s}:{s}", .{ a.remote_ufrag.items, &a.local_ufrag }) catch return;
    b.add(stun.attr.username, user) catch return;
    const local_pref: u32 = (l.c.priority >> 8) & 0xffff;
    b.addU32(stun.attr.priority, cand.priority(.prflx, @intCast(local_pref), 1)) catch return;
    b.addU64(if (a.role == .controlling) stun.attr.ice_controlling else stun.attr.ice_controlled, a.tiebreaker) catch return;
    if (use_candidate and a.role == .controlling) b.add(stun.attr.use_candidate, "") catch return;
    b.addIntegrity(a.remote_pwd.items) catch return;
    b.addFingerprint() catch return;
    ck.len = b.len;
    if (p.state == .waiting or p.state == .failed) p.state = .in_progress;
    a.sendFrom(l.base, a.remotes.items[p.remote].address, ck.msg[0..ck.len]);
    a.checks.append(a.gpa, ck) catch {};
}

fn respond(a: *Agent, base: Base, to: Address, req: stun.Message, error_code: ?u16) void {
    var buf: [256]u8 = undefined;
    var b = stun.Builder.init(&buf, .binding, if (error_code == null) .success else .failure, req.txid);
    if (error_code) |code| {
        b.addErrorCode(code, "Role Conflict") catch return;
    } else {
        b.addXorAddress(stun.attr.xor_mapped_address, to) catch return;
    }
    b.addIntegrity(&a.local_pwd) catch return;
    b.addFingerprint() catch return;
    a.sendFrom(base, to, b.bytes());
}

// ---- receiving ----------------------------------------------------------------------------

/// Handles a datagram received on `sockets[socket]` from `from`. STUN and TURN traffic is
/// consumed; anything else (DTLS, SRTP) is returned for the transport to demultiplex.
pub fn receive(a: *Agent, socket: u8, from: Address, data: []const u8, now: u64) ?[]const u8 {
    a.now = now;
    if (a.state == .closed) return null;
    for (a.turns.items, 0..) |*t, ti| {
        if (!t.owns(socket, from)) continue;
        switch (t.handle(data, now)) {
            .none => {},
            .allocated => a.turnAllocated(@intCast(ti)),
            .failed => {
                a.turn_settled.items[ti] = true;
                a.checkGatheringDone();
            },
            .data => |d| return a.receiveOnBase(.{ .socket = socket, .turn = @intCast(ti) }, d.peer, d.payload),
        }
        return null;
    }
    return a.receiveOnBase(.{ .socket = socket }, from, data);
}

fn receiveOnBase(a: *Agent, base: Base, from: Address, data: []const u8) ?[]const u8 {
    if (!stun.isStun(data)) return data;
    const m = stun.Message.parse(data) catch return null;
    if (!m.checkFingerprint()) return null;
    if (m.method != .binding) return null;
    switch (m.class) {
        .request => a.handleRequest(base, from, m),
        .success, .failure => a.handleResponse(base, from, m),
        .indication => {}, // keepalives
    }
    return null;
}

fn turnAllocated(a: *Agent, ti: u8) void {
    const t = &a.turns.items[ti];
    a.turn_settled.items[ti] = true;
    if (!t.mapped.isUnspecified()) {
        const host = a.sockets[t.socket].local;
        if (!t.mapped.eql(host)) a.addLocal(.srflx, t.mapped, host, .{ .socket = t.socket }, false, 2000 + @as(u32, t.socket)) catch {};
    }
    a.addLocal(.relay, t.relayed, t.mapped, .{ .socket = t.socket, .turn = ti }, true, 3000 + @as(u32, ti)) catch {};
    a.checkGatheringDone();
}

fn handleRequest(a: *Agent, base: Base, from: Address, m: stun.Message) void {
    const user = m.get(stun.attr.username) orelse return;
    if (!std.mem.startsWith(u8, user, &a.local_ufrag) or user.len <= a.local_ufrag.len or user[a.local_ufrag.len] != ':') return;
    if (!m.checkIntegrity(&a.local_pwd)) return;

    // Role conflict (RFC 8445 7.3.1.1).
    if (a.role == .controlling) {
        if (m.getU64(stun.attr.ice_controlling)) |theirs| {
            if (a.tiebreaker >= theirs) return a.respond(base, from, m, 487);
            a.switchRole(.controlled);
        }
    } else if (m.getU64(stun.attr.ice_controlled)) |theirs| {
        if (a.tiebreaker >= theirs) {
            a.switchRole(.controlling);
        } else return a.respond(base, from, m, 487);
    }
    a.respond(base, from, m, null);

    const li = a.localForBase(base) orelse return;
    var ri: ?u16 = null;
    for (a.remotes.items, 0..) |r, i| if (r.address.eql(from)) {
        ri = @intCast(i);
    };
    if (ri == null) {
        // Peer-reflexive: the peer reached us from an address it has not signalled.
        var c: Candidate = .{ .priority = m.getU32(stun.attr.priority) orelse cand.priority(.prflx, 65535, 1), .address = from, .type = .prflx };
        c.setFoundation("prflx");
        ri = a.findOrAddRemote(c) catch return;
    }
    a.addPair(li, ri.?) catch return;
    const pi = a.findPair(li, ri.?) orelse return;
    const p = &a.pairs.items[pi];
    if (m.has(stun.attr.use_candidate) and a.role == .controlled) {
        p.use_candidate_seen = true;
        if (p.state == .succeeded) a.nominate(pi);
    }
    if (a.state == .new) a.startChecking();
    // Triggered check (RFC 8445 7.3.1.4), unless one is already running or done.
    if (p.state == .waiting or p.state == .failed) {
        for (a.triggered.items) |t| if (t == pi) return;
        a.triggered.append(a.gpa, pi) catch {};
    }
}

fn handleResponse(a: *Agent, base: Base, from: Address, m: stun.Message) void {
    // STUN server answers for srflx gathering carry no integrity.
    for (a.gathers.items) |*g| {
        if (!std.mem.eql(u8, &g.txid, &m.txid)) continue;
        if (g.done) return;
        g.done = true;
        if (m.class == .success) if (m.mappedAddress()) |mapped| {
            const host = a.sockets[g.socket].local;
            if (!mapped.eql(host)) a.addLocal(.srflx, mapped, host, .{ .socket = g.socket }, false, 2000 + @as(u32, g.socket)) catch {};
        };
        a.checkGatheringDone();
        return;
    }
    const ci = for (a.checks.items, 0..) |ck, i| {
        if (std.mem.eql(u8, &ck.txid, &m.txid)) break i;
    } else return;
    if (!m.checkIntegrity(a.remote_pwd.items)) return;
    const ck = a.checks.swapRemove(ci);
    const p = &a.pairs.items[ck.pair];
    // Responses must come back on the same path (RFC 8445 7.2.5.2.1).
    if (!a.remotes.items[p.remote].address.eql(from) or !a.locals.items[p.local].base.eql(base)) {
        p.state = .failed;
        return;
    }
    if (m.class == .failure) {
        if (m.errorCode() == 487) {
            a.switchRole(if (ck.use_candidate or a.role == .controlling) .controlled else .controlling);
            p.state = .waiting;
            a.triggered.append(a.gpa, ck.pair) catch {};
        } else p.state = .failed;
        return;
    }
    p.state = .succeeded;
    p.last_response = a.now;
    if (a.first_valid_at == null) a.first_valid_at = a.now;
    if (ck.use_candidate and a.role == .controlling) {
        a.nominating = false;
        a.nominate(ck.pair);
    } else if (a.role == .controlled and p.use_candidate_seen) {
        a.nominate(ck.pair);
    } else {
        a.updateProvisional();
    }
}

fn nominate(a: *Agent, pi: u16) void {
    const p = &a.pairs.items[pi];
    p.nominated = true;
    if (a.selected) |s| if (a.pairs.items[s].nominated and s != pi) return; // keep the first nomination
    a.select(pi);
}

/// Before nomination, use the best valid pair so DTLS can start early.
fn updateProvisional(a: *Agent) void {
    if (a.selected) |s| if (a.pairs.items[s].nominated) return;
    var best: ?u16 = null;
    for (a.pairs.items, 0..) |p, i| if (p.state == .succeeded) {
        if (best == null or p.priority > a.pairs.items[best.?].priority) best = @intCast(i);
    };
    if (best) |b| a.select(b);
}

fn select(a: *Agent, pi: u16) void {
    a.selected = pi;
    a.fallback = null;
    const p = &a.pairs.items[pi];
    if (p.next_consent == 0) p.next_consent = a.now + a.consentInterval();
    a.setState(.connected);
}

fn consentInterval(a: *Agent) u64 {
    // Randomised to 0.8..1.2 of the interval (RFC 7675 5.1).
    var r: [1]u8 = undefined;
    a.io.random(&r);
    return a.config.consent_interval_ms * (80 + @as(u64, r[0]) % 41) / 100;
}

// ---- timers -------------------------------------------------------------------------------

pub fn nextTimeout(a: *const Agent) ?u64 {
    var t: ?u64 = null;
    const Min = struct {
        fn f(cur: ?u64, v: u64) ?u64 {
            return if (cur) |c| @min(c, v) else v;
        }
    };
    if (a.state == .closed or a.state == .failed) return null;
    for (a.checks.items) |ck| t = Min.f(t, ck.next_at);
    for (a.gathers.items) |g| if (!g.done) {
        t = Min.f(t, g.next_at);
    };
    for (a.turns.items) |*tc| if (tc.nextTimeout()) |v| {
        t = Min.f(t, v);
    };
    if (a.hasRemoteCredentials() and (a.triggered.items.len > 0 or a.hasWaiting())) t = Min.f(t, a.next_check_at);
    if (a.selected) |s| t = Min.f(t, a.pairs.items[s].next_consent);
    if (a.role == .controlling and a.first_valid_at != null and !a.isNominated() and !a.nominating)
        t = Min.f(t, a.first_valid_at.? + a.config.nomination_delay_ms);
    if (a.state == .checking) t = Min.f(t, a.checking_since + a.config.failed_after_ms);
    return t;
}

fn hasWaiting(a: *const Agent) bool {
    for (a.pairs.items) |p| if (p.state == .waiting) return true;
    return false;
}

fn isNominated(a: *const Agent) bool {
    const s = a.selected orelse return false;
    return a.pairs.items[s].nominated;
}

pub fn poll(a: *Agent, now: u64) void {
    a.now = now;
    if (a.state == .closed or a.state == .failed) return;

    for (a.gathers.items) |*g| if (!g.done and now >= g.next_at) {
        if (g.attempts >= 4) {
            g.done = true;
        } else {
            g.attempts += 1;
            g.next_at = now + 300 * @as(u64, g.attempts);
            a.sendGather(g);
        }
    };
    for (a.turns.items, 0..) |*t, ti| if (t.poll(now) == .failed) {
        a.turn_settled.items[ti] = true;
    };
    a.checkGatheringDone();

    // Retransmit checks; give up on a pair after max attempts.
    var i: usize = 0;
    while (i < a.checks.items.len) {
        const ck = &a.checks.items[i];
        if (now < ck.next_at) {
            i += 1;
            continue;
        }
        if (ck.attempts >= max_check_attempts) {
            const p = &a.pairs.items[ck.pair];
            if (p.state == .in_progress) p.state = .failed;
            if (ck.use_candidate) a.nominating = false;
            _ = a.checks.swapRemove(i);
            continue;
        }
        ck.attempts += 1;
        ck.rto = @min(ck.rto * 2, 1600);
        ck.next_at = now + ck.rto;
        const p = a.pairs.items[ck.pair];
        a.sendFrom(a.locals.items[p.local].base, a.remotes.items[p.remote].address, ck.msg[0..ck.len]);
        i += 1;
    }

    // One new check per Ta: triggered first, then the best waiting pair.
    if (a.hasRemoteCredentials() and now >= a.next_check_at) {
        var next: ?u16 = null;
        if (a.triggered.items.len > 0) {
            next = a.triggered.orderedRemove(0);
        } else {
            for (a.pairs.items, 0..) |p, pi| if (p.state == .waiting) {
                if (next == null or p.priority > a.pairs.items[next.?].priority) next = @intCast(pi);
            };
        }
        if (next) |pi| {
            const nominate_now = a.role == .controlling and a.pairs.items[pi].use_candidate_seen;
            a.startCheck(pi, nominate_now);
            a.next_check_at = now + a.config.check_interval_ms;
        }
    }

    // Regular nomination: after a short wait, nominate the best valid pair.
    if (a.role == .controlling and !a.isNominated() and !a.nominating) {
        if (a.first_valid_at) |t0| if (now >= t0 + a.config.nomination_delay_ms) {
            var best: ?u16 = null;
            for (a.pairs.items, 0..) |p, pi| if (p.state == .succeeded) {
                if (best == null or p.priority > a.pairs.items[best.?].priority) best = @intCast(pi);
            };
            if (best) |b| {
                a.nominating = true;
                a.startCheck(b, true);
            }
        };
    }

    // Consent freshness on the selected pair (RFC 7675).
    if (a.selected) |s| {
        const p = &a.pairs.items[s];
        if (now >= p.next_consent) {
            p.next_consent = now + a.consentInterval();
            a.startCheck(s, false);
        }
        const silent = now -| p.last_response;
        if (silent >= a.config.failed_after_ms) {
            a.setState(.failed);
        } else if (silent >= a.config.disconnected_after_ms) {
            a.setState(.disconnected);
        } else if (a.state == .disconnected) {
            a.setState(.connected);
        }
    } else if (a.state == .checking and now >= a.checking_since + a.config.failed_after_ms) {
        a.setState(.failed);
    }
}

pub fn close(a: *Agent) void {
    for (a.turns.items) |*t| t.close();
    a.setState(.closed);
}

pub fn localUfrag(a: *const Agent) []const u8 {
    return &a.local_ufrag;
}

pub fn localPwd(a: *const Agent) []const u8 {
    return &a.local_pwd;
}

// ---- tests --------------------------------------------------------------------------------

const testing = std.testing;

/// Two agents joined by an in-memory network. Each agent has one host socket.
const TestNet = struct {
    gpa: std.mem.Allocator,
    queue: std.ArrayList(Packet) = .empty,
    candidates: [2]std.ArrayList(Candidate) = .{ .empty, .empty },
    states: [2]State = .{ .new, .new },
    app: [2]usize = .{ 0, 0 },

    const Packet = struct { to_agent: u8, from: Address, data: []u8 };
    const Port = struct { net: *TestNet, agent: u8 };

    fn deinit(n: *TestNet) void {
        for (n.queue.items) |p| n.gpa.free(p.data);
        n.queue.deinit(n.gpa);
        for (&n.candidates) |*c| c.deinit(n.gpa);
    }

    fn sendFn(ctx: *anyopaque, to: Address, data: []const u8) void {
        const port: *Port = @ptrCast(@alignCast(ctx));
        const n = port.net;
        const target: u8 = if (to.port == 1000) 0 else if (to.port == 2000) 1 else return;
        const from = if (port.agent == 0) addr0 else addr1;
        n.queue.append(n.gpa, .{ .to_agent = target, .from = from, .data = n.gpa.dupe(u8, data) catch unreachable }) catch unreachable;
    }

    const addr0 = Address.ip4(.{ 10, 0, 0, 1 }, 1000);
    const addr1 = Address.ip4(.{ 10, 0, 0, 2 }, 2000);
};

const Observer = struct {
    net: *TestNet,
    idx: u8,
    fn onCandidate(ctx: *anyopaque, c: *const Candidate) void {
        const o: *Observer = @ptrCast(@alignCast(ctx));
        o.net.candidates[o.idx].append(o.net.gpa, c.*) catch unreachable;
    }
    fn onDone(_: *anyopaque) void {}
    fn onState(ctx: *anyopaque, s: State) void {
        const o: *Observer = @ptrCast(@alignCast(ctx));
        o.net.states[o.idx] = s;
    }
};

test "two agents connect, nominate, exchange data and keep consent" {
    const gpa = testing.allocator;
    var n: TestNet = .{ .gpa = gpa };
    defer n.deinit();
    var ports = [2]TestNet.Port{ .{ .net = &n, .agent = 0 }, .{ .net = &n, .agent = 1 } };
    var obs = [2]Observer{ .{ .net = &n, .idx = 0 }, .{ .net = &n, .idx = 1 } };
    const s0 = [_]Socket{.{ .ctx = &ports[0], .sendFn = TestNet.sendFn, .local = TestNet.addr0 }};
    const s1 = [_]Socket{.{ .ctx = &ports[1], .sendFn = TestNet.sendFn, .local = TestNet.addr1 }};
    var a0 = try Agent.init(gpa, testing.io, .{ .role = .controlling }, &s0, .{ .ctx = &obs[0], .candidate = Observer.onCandidate, .gathering_done = Observer.onDone, .state = Observer.onState });
    defer a0.deinit();
    var a1 = try Agent.init(gpa, testing.io, .{ .role = .controlled }, &s1, .{ .ctx = &obs[1], .candidate = Observer.onCandidate, .gathering_done = Observer.onDone, .state = Observer.onState });
    defer a1.deinit();

    try a0.gather(0);
    try a1.gather(0);
    try a0.setRemoteCredentials(a1.localUfrag(), a1.localPwd());
    try a1.setRemoteCredentials(a0.localUfrag(), a0.localPwd());
    // Only agent 1 learns the other's candidate; agent 0 must find agent 1 as peer-reflexive.
    try a1.addRemoteCandidate(n.candidates[0].items[0]);

    const agents = [2]*Agent{ &a0, &a1 };
    var now: u64 = 0;
    while (now < 3000) : (now += 10) {
        while (n.queue.items.len > 0) {
            const p = n.queue.orderedRemove(0);
            defer gpa.free(p.data);
            if (agents[p.to_agent].receive(0, p.from, p.data, now)) |_| n.app[p.to_agent] += 1;
        }
        a0.poll(now);
        a1.poll(now);
    }
    try testing.expectEqual(State.connected, a0.state);
    try testing.expectEqual(State.connected, a1.state);
    try testing.expect(a0.isNominated());
    try testing.expect(a1.isNominated());
    try testing.expectEqual(cand.Type.prflx, a0.selectedPair().?.remote.type);

    try a0.send("hello");
    try a1.send("hi");
    while (n.queue.items.len > 0) {
        const p = n.queue.orderedRemove(0);
        defer gpa.free(p.data);
        if (agents[p.to_agent].receive(0, p.from, p.data, now)) |d| {
            try testing.expect(std.mem.eql(u8, d, "hello") or std.mem.eql(u8, d, "hi"));
            n.app[p.to_agent] += 1;
        }
    }
    try testing.expectEqual(@as(usize, 1), n.app[0]);
    try testing.expectEqual(@as(usize, 1), n.app[1]);

    // Keep running past several consent intervals: still connected.
    while (now < 40_000) : (now += 50) {
        while (n.queue.items.len > 0) {
            const p = n.queue.orderedRemove(0);
            defer gpa.free(p.data);
            _ = agents[p.to_agent].receive(0, p.from, p.data, now);
        }
        a0.poll(now);
        a1.poll(now);
    }
    try testing.expectEqual(State.connected, a0.state);
    // Cut the network: consent expires.
    while (now < 80_000) : (now += 50) {
        for (n.queue.items) |p| gpa.free(p.data);
        n.queue.clearRetainingCapacity();
        a0.poll(now);
    }
    try testing.expectEqual(State.failed, a0.state);
}
