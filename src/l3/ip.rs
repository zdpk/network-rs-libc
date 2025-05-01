use crate::util::addr::fmt_ip;

use super::checksum;

// https://github.com/torvalds/linux/blob/master/include/uapi/linux/ip.h#L87
#[repr(C, packed)]
pub struct Ipv4Hdr {
    // version(4bits) and ip header length(4bits)
    pub version_ihl: u8,
    // type of service
    pub tos: u8,
    // total length(ip header + ip payload)
    pub tot_len: u16,
    pub id: u16,
    pub frag_off: u16,
    pub ttl: u8,
    pub protocol: u8,
    // include ip header, and not include ip payload
    pub check: u16,
    pub saddr: u32,
    pub daddr: u32,
}

impl Ipv4Hdr {
    pub fn new(buf: &mut [u8]) -> &mut Self {
        unsafe { &mut *(buf.as_mut_ptr() as *mut Self) }
    }

    pub fn print_ip_hdr(&self) {
        println!("---------------IP Header---------------");
        println!("version: {}", self.version_ihl >> 4);
        println!("ihl: {}", self.version_ihl & 0x0F);
        println!("tos: {}", self.tos);
        println!("tot_len: {}", u16::from_be(self.tot_len));
        println!("id: {}", u16::from_be(self.id));
        println!("frag_off: 0x{:04x}", u16::from_be(self.frag_off));
        println!("ttl: {}", self.ttl);
        println!("protocol: {}", self.protocol);
        println!("check: 0x{:04x}", u16::from_be(self.check));
        println!("saddr: {}", fmt_ip(self.saddr.to_ne_bytes()));
        println!("daddr: {}", fmt_ip(self.daddr.to_ne_bytes()));
        println!("----------------------------------------");
    }
}
