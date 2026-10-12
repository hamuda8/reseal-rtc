//! A deliberately trivial H.264 encoder for interop testing only (not part of the library):
//! Constrained Baseline, CAVLC, IDR frames made of I_PCM macroblocks (raw samples) and
//! P frames made of P_Skip macroblocks. Valid streams, no compression; enough for a browser
//! to decode real pictures we sent over RTP.

const std = @import("std");

pub const Encoder = struct {
    width_mbs: u32,
    height_mbs: u32,
    frame_num: u32 = 0,
    idr_id: u32 = 0,
    out: std.ArrayList(u8) = .empty,

    pub fn init(width: u32, height: u32) Encoder {
        return .{ .width_mbs = width / 16, .height_mbs = height / 16 };
    }

    pub fn deinit(e: *Encoder, gpa: std.mem.Allocator) void {
        e.out.deinit(gpa);
    }

    /// An access unit in Annex-B. Keyframes carry SPS + PPS + IDR; others are one P slice.
    /// `shade` picks the picture colour so successive keyframes differ.
    pub fn encode(e: *Encoder, gpa: std.mem.Allocator, keyframe: bool, shade: u8) ![]const u8 {
        e.out.clearRetainingCapacity();
        var bw: BitWriter = .{ .gpa = gpa };
        defer bw.bits.deinit(gpa);
        if (keyframe) {
            bw.reset();
            try e.sps(&bw);
            try e.nal(gpa, 3, 7, &bw);
            bw.reset();
            try pps(&bw);
            try e.nal(gpa, 3, 8, &bw);
            bw.reset();
            try e.idr(&bw, shade);
            try e.nal(gpa, 3, 5, &bw);
            e.frame_num = 1;
            e.idr_id +%= 1;
        } else {
            bw.reset();
            try e.pSkip(&bw);
            try e.nal(gpa, 2, 1, &bw);
            e.frame_num = (e.frame_num + 1) % 16;
        }
        return e.out.items;
    }

    fn sps(e: *Encoder, w: *BitWriter) !void {
        try w.u(8, 66); // profile_idc: Baseline
        try w.u(8, 0xE0); // constraint_set0/1/2: Constrained Baseline ("42e0..")
        try w.u(8, 31); // level 3.1
        try w.ue(0); // seq_parameter_set_id
        try w.ue(0); // log2_max_frame_num_minus4 -> 16 frame numbers
        try w.ue(2); // pic_order_cnt_type 2: output order = decode order
        try w.ue(1); // max_num_ref_frames
        try w.u(1, 0); // gaps_in_frame_num_value_allowed_flag
        try w.ue(e.width_mbs - 1);
        try w.ue(e.height_mbs - 1);
        try w.u(1, 1); // frame_mbs_only_flag
        try w.u(1, 1); // direct_8x8_inference_flag
        try w.u(1, 0); // frame_cropping_flag
        try w.u(1, 0); // vui_parameters_present_flag
        try w.trailing();
    }

    fn pps(w: *BitWriter) !void {
        try w.ue(0); // pic_parameter_set_id
        try w.ue(0); // seq_parameter_set_id
        try w.u(1, 0); // entropy_coding_mode_flag: CAVLC
        try w.u(1, 0); // bottom_field_pic_order_in_frame_present_flag
        try w.ue(0); // num_slice_groups_minus1
        try w.ue(0); // num_ref_idx_l0_default_active_minus1
        try w.ue(0); // num_ref_idx_l1_default_active_minus1
        try w.u(1, 0); // weighted_pred_flag
        try w.u(2, 0); // weighted_bipred_idc
        try w.se(0); // pic_init_qp_minus26
        try w.se(0); // pic_init_qs_minus26
        try w.se(0); // chroma_qp_index_offset
        try w.u(1, 1); // deblocking_filter_control_present_flag
        try w.u(1, 0); // constrained_intra_pred_flag
        try w.u(1, 0); // redundant_pic_cnt_present_flag
        try w.trailing();
    }

    fn idr(e: *Encoder, w: *BitWriter, shade: u8) !void {
        try w.ue(0); // first_mb_in_slice
        try w.ue(7); // slice_type: I (all slices)
        try w.ue(0); // pic_parameter_set_id
        try w.u(4, 0); // frame_num
        try w.ue(e.idr_id & 0xffff); // idr_pic_id
        try w.u(1, 0); // no_output_of_prior_pics_flag
        try w.u(1, 0); // long_term_reference_flag
        try w.se(0); // slice_qp_delta
        try w.ue(1); // disable_deblocking_filter_idc
        const mbs = e.width_mbs * e.height_mbs;
        for (0..mbs) |mb| {
            try w.ue(25); // mb_type I_PCM
            while (w.len % 8 != 0) try w.u(1, 0); // pcm_alignment_zero_bit
            const mx: u32 = @intCast(mb % e.width_mbs);
            const my: u32 = @intCast(mb / e.width_mbs);
            for (0..256) |i| {
                // A gradient that moves with `shade`; never 0 (old decoders reject it).
                const x = mx * 16 + @as(u32, @intCast(i % 16));
                const y = my * 16 + @as(u32, @intCast(i / 16));
                try w.u(8, 16 + ((x + y + shade) % 220));
            }
            for (0..64) |_| try w.u(8, 128 + @as(u32, shade % 64)); // Cb
            for (0..64) |_| try w.u(8, 128 - @as(u32, shade % 64)); // Cr
        }
        try w.trailing();
    }

    fn pSkip(e: *Encoder, w: *BitWriter) !void {
        try w.ue(0); // first_mb_in_slice
        try w.ue(5); // slice_type: P (all slices)
        try w.ue(0); // pic_parameter_set_id
        try w.u(4, e.frame_num);
        try w.u(1, 0); // num_ref_idx_active_override_flag
        try w.u(1, 0); // ref_pic_list_modification_flag_l0
        try w.u(1, 0); // adaptive_ref_pic_marking_mode_flag
        try w.se(0); // slice_qp_delta
        try w.ue(1); // disable_deblocking_filter_idc
        try w.ue(e.width_mbs * e.height_mbs); // mb_skip_run: every macroblock skipped
        try w.trailing();
    }

    /// Start code, NAL header and the RBSP with emulation prevention bytes.
    fn nal(e: *Encoder, gpa: std.mem.Allocator, ref_idc: u8, nal_type: u8, w: *BitWriter) !void {
        try e.out.appendSlice(gpa, &.{ 0, 0, 0, 1, (ref_idc << 5) | nal_type });
        var zeros: u32 = 0;
        for (w.bytes()) |b| {
            if (zeros >= 2 and b <= 3) {
                try e.out.append(gpa, 3);
                zeros = 0;
            }
            try e.out.append(gpa, b);
            zeros = if (b == 0) zeros + 1 else 0;
        }
    }
};

const BitWriter = struct {
    gpa: std.mem.Allocator,
    bits: std.ArrayList(u8) = .empty,
    len: usize = 0, // in bits

    fn reset(w: *BitWriter) void {
        w.bits.clearRetainingCapacity();
        w.len = 0;
    }

    fn bit(w: *BitWriter, b: u1) !void {
        if (w.len % 8 == 0) try w.bits.append(w.gpa, 0);
        if (b == 1) w.bits.items[w.len / 8] |= @as(u8, 0x80) >> @intCast(w.len % 8);
        w.len += 1;
    }

    fn u(w: *BitWriter, n: u6, v: u32) !void {
        var i: u6 = n;
        while (i > 0) {
            i -= 1;
            try w.bit(@intCast((v >> @intCast(i)) & 1));
        }
    }

    /// Exp-Golomb unsigned.
    fn ue(w: *BitWriter, v: u32) !void {
        const x = v + 1;
        const nbits: u6 = @intCast(32 - @clz(x));
        try w.u(nbits - 1, 0);
        try w.u(nbits, x);
    }

    fn se(w: *BitWriter, v: i32) !void {
        try w.ue(if (v > 0) @intCast(2 * v - 1) else @intCast(-2 * v));
    }

    fn trailing(w: *BitWriter) !void {
        try w.bit(1);
        while (w.len % 8 != 0) try w.bit(0);
    }

    fn bytes(w: *const BitWriter) []const u8 {
        return w.bits.items;
    }
};

test "encoder emits SPS/PPS/IDR then P" {
    const gpa = std.testing.allocator;
    var e = Encoder.init(64, 48);
    defer e.deinit(gpa);
    const key = try e.encode(gpa, true, 0);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 1, 0x67, 66, 0xE0, 31 }, key[0..8]);
    const p = try e.encode(gpa, false, 0);
    try std.testing.expectEqual(@as(u8, 0x41), p[4]);
}
