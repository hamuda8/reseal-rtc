//! Data channels (RTCDataChannel): not implemented yet. This file records the plan so the
//! layer slots in without reshaping the others.
//!
//! Wire stack, bottom up:
//!   DTLS application data records   - already delivered by dtls/Conn.zig through
//!                                     `Callbacks.data`, and surfaced by PeerTransport as
//!                                     `Events.data`; sending is `Conn.sendApplicationData`.
//!   SCTP (RFC 4960) over DTLS (RFC 8261), as profiled by RFC 8831:
//!     - one association per PeerConnection, ports from a=sctp-port (5000 by default),
//!     - INIT/INIT-ACK/COOKIE-ECHO/COOKIE-ACK, DATA/SACK, HEARTBEAT, FORWARD-TSN (RFC 3758)
//!       for unordered/partially reliable channels, RE-CONFIG (RFC 6525) to close streams,
//!     - CRC32c checksums (std.hash.crc has the Castagnoli variant),
//!     - message interleaving (I-DATA, RFC 8260) is optional and can wait,
//!     - max message size from a=max-message-size (browsers send 262144).
//!   DCEP (RFC 8832): DATA_CHANNEL_OPEN / DATA_CHANNEL_ACK on the stream, PPIDs 50 (DCEP),
//!   51 (string), 53 (binary), 56/57 (empty string/binary).
//!
//! SDP: an `m=application 9 UDP/DTLS/SCTP webrtc-datachannel` section with a=sctp-port and
//! a=max-message-size, in the same BUNDLE group. sdp/sdp.zig already parses such m-lines,
//! and peer.zig currently answers them with port 0 (rejected) so negotiation stays valid.
//!
//! Proposed API on PeerConnection:
//!   createDataChannel(label, .{ .ordered, .max_retransmits, .max_packet_life_ms, .negotiated_id })
//!   events: .data_channel_open{id, label}, .data_channel_message{id, data, binary}, .data_channel_closed{id}
//!   sendData(id, bytes, binary)

pub const sctp_default_port = 5000;
pub const ppid = struct {
    pub const dcep = 50;
    pub const string = 51;
    pub const binary = 53;
    pub const string_empty = 56;
    pub const binary_empty = 57;
};
