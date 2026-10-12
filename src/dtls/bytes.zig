//! Big-endian readers and writers for TLS-style structures with length-prefixed vectors.

const std = @import("std");

pub const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn init(buf: []const u8) Reader {
        return .{ .buf = buf };
    }

    pub fn rest(r: *const Reader) []const u8 {
        return r.buf[r.pos..];
    }

    pub fn done(r: *const Reader) bool {
        return r.pos == r.buf.len;
    }

    pub fn bytes(r: *Reader, n: usize) ![]const u8 {
        if (r.pos + n > r.buf.len) return error.Truncated;
        defer r.pos += n;
        return r.buf[r.pos..][0..n];
    }

    pub fn int(r: *Reader, comptime T: type) !T {
        const n = @divExact(@typeInfo(T).int.bits, 8);
        return std.mem.readInt(T, (try r.bytes(n))[0..n], .big);
    }

    /// A vector with an n-byte length prefix (n = 1, 2 or 3).
    pub fn vec(r: *Reader, comptime n: usize) ![]const u8 {
        const len: usize = switch (n) {
            1 => try r.int(u8),
            2 => try r.int(u16),
            3 => try r.int(u24),
            else => @compileError("bad length size"),
        };
        return r.bytes(len);
    }
};

/// Appends to a growable buffer. Length-prefixed vectors are opened with `begin(n)` and
/// closed with `end()`, which fills in the length.
pub const Writer = struct {
    gpa: std.mem.Allocator,
    list: std.ArrayList(u8) = .empty,
    stack: [8]struct { at: usize, n: u8 } = undefined,
    depth: usize = 0,

    pub fn init(gpa: std.mem.Allocator) Writer {
        return .{ .gpa = gpa };
    }

    pub fn deinit(w: *Writer) void {
        w.list.deinit(w.gpa);
    }

    pub fn written(w: *const Writer) []u8 {
        return w.list.items;
    }

    pub fn toOwned(w: *Writer) ![]u8 {
        return w.list.toOwnedSlice(w.gpa);
    }

    pub fn put(w: *Writer, data: []const u8) !void {
        try w.list.appendSlice(w.gpa, data);
    }

    pub fn int(w: *Writer, comptime T: type, v: T) !void {
        const n = @divExact(@typeInfo(T).int.bits, 8);
        var tmp: [n]u8 = undefined;
        std.mem.writeInt(T, &tmp, v, .big);
        try w.put(&tmp);
    }

    pub fn begin(w: *Writer, n: u8) !void {
        w.stack[w.depth] = .{ .at = w.list.items.len, .n = n };
        w.depth += 1;
        try w.list.appendNTimes(w.gpa, 0, n);
    }

    pub fn end(w: *Writer) void {
        w.depth -= 1;
        const e = w.stack[w.depth];
        const len = w.list.items.len - e.at - e.n;
        const dst = w.list.items[e.at..][0..e.n];
        switch (e.n) {
            1 => dst[0] = @intCast(len),
            2 => std.mem.writeInt(u16, dst[0..2], @intCast(len), .big),
            3 => std.mem.writeInt(u24, dst[0..3], @intCast(len), .big),
            else => unreachable,
        }
    }

    pub fn vec(w: *Writer, n: u8, data: []const u8) !void {
        try w.begin(n);
        try w.put(data);
        w.end();
    }
};

test "writer vectors and reader" {
    var w = Writer.init(std.testing.allocator);
    defer w.deinit();
    try w.int(u16, 0xFEFD);
    try w.begin(2);
    try w.vec(1, "ab");
    w.end();
    try std.testing.expectEqualSlices(u8, &.{ 0xFE, 0xFD, 0, 3, 2, 'a', 'b' }, w.written());
    var r = Reader.init(w.written());
    try std.testing.expectEqual(@as(u16, 0xFEFD), try r.int(u16));
    var inner = Reader.init(try r.vec(2));
    try std.testing.expectEqualStrings("ab", try inner.vec(1));
    try std.testing.expect(r.done());
}
