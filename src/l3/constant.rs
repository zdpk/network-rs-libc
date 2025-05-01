pub const IP_DF: u16 = 0x4000;

pub const IP_HDR_MIN_LEN: usize = 20;
pub const ICMP_HDR_MIN_LEN: usize = 8;
pub const ICMP_PAYLOAD_LEN: usize = 56;
pub const ICMP_TIMESTAMP_LEN: usize = 16;
pub const ICMP_PATTERN_LEN: usize = 40;

// Common ICMP Types (IPv4)
pub const ICMP_ECHO_REPLY: u8 = 0; // Echo Reply
pub const ICMP_DEST_UNREACH: u8 = 3; // Destination Unreachable
pub const ICMP_SOURCE_QUENCH: u8 = 4; // Source Quench
pub const ICMP_REDIRECT: u8 = 5; // Redirect
pub const ICMP_ECHO_REQUEST: u8 = 8; // Echo Request
pub const ICMP_ROUTER_ADVERT: u8 = 9; // Router Advertisement
pub const ICMP_ROUTER_SOLICIT: u8 = 10; // Router Solicitation
pub const ICMP_TIME_EXCEEDED: u8 = 11; // Time Exceeded
pub const ICMP_PARAMETERPROB: u8 = 12; // Parameter Problem
pub const ICMP_TIMESTAMP_REQUEST: u8 = 13; // Timestamp Request
pub const ICMP_TIMESTAMP_REPLY: u8 = 14; // Timestamp Reply
pub const ICMP_INFO_REQUEST: u8 = 15; // Information Request (Deprecated)
pub const ICMP_INFO_REPLY: u8 = 16; // Information Reply (Deprecated)
pub const ICMP_ADDRESS: u8 = 17; // Address Mask Request (Deprecated)
pub const ICMP_ADDRESSREPLY: u8 = 18; // Address Mask Reply (Deprecated)

// Codes for ICMP_DEST_UNREACH (Type 3)
pub const ICMP_NET_UNREACH: u8 = 0; // Network Unreachable
pub const ICMP_HOST_UNREACH: u8 = 1; // Host Unreachable
pub const ICMP_PROT_UNREACH: u8 = 2; // Protocol Unreachable
pub const ICMP_PORT_UNREACH: u8 = 3; // Port Unreachable
pub const ICMP_FRAG_NEEDED: u8 = 4; // Fragmentation Needed and Don't Fragment was Set
pub const ICMP_SR_FAILED: u8 = 5; // Source Route Failed
pub const ICMP_NET_UNKNOWN: u8 = 6; // Network Unknown
pub const ICMP_HOST_UNKNOWN: u8 = 7; // Host Unknown
pub const ICMP_HOST_ISOLATED: u8 = 8; // Source Host Isolated
pub const ICMP_NET_ANO: u8 = 9; // Communication with Destination Network is Administratively Prohibited
pub const ICMP_HOST_ANO: u8 = 10; // Communication with Destination Host is Administratively Prohibited
pub const ICMP_NET_UNR_TOS: u8 = 11; // Network Unreachable for Type Of Service
pub const ICMP_HOST_UNR_TOS: u8 = 12; // Host Unreachable for Type Of Service
pub const ICMP_PKT_FILTERED: u8 = 13; // Communication Administratively Prohibited (Packet Filtered)
pub const ICMP_PREC_VIOLATION: u8 = 14; // Host Precedence Violation
pub const ICMP_PREC_CUTOFF: u8 = 15; // Precedence cutoff in effect
