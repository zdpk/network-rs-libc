// https://github.com/torvalds/linux/blob/master/include/uapi/linux/icmp.h#L89

use super::{
    checksum::calc_checksum,
    constant::{ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST, ICMP_PATTERN_LEN, ICMP_PAYLOAD_LEN},
};

pub const ICMP_NUM_PATTERN: [u8; ICMP_PATTERN_LEN] = num_pattern::<ICMP_PATTERN_LEN>();

pub const fn num_pattern<const LEN: usize>() -> [u8; LEN] {
    let mut pat = [0u8; LEN];
    let mut i = 0;
    let start = 0x10;

    while i < LEN {
        pat[i] = (start + i) as u8;
        i += 1;
    }

    pat
}

#[repr(C, packed)]
pub struct IcmpHdr {
    pub r#type: u8,
    pub code: u8,
    pub checksum: u16,
    pub ext: IcmpHdrExt,
}

impl IcmpHdr {
    pub fn new(buf: &mut [u8]) -> &mut Self {
        unsafe { &mut *(buf.as_mut_ptr() as *mut Self) }
    }

    pub fn print_icmp_hdr(&self) {
        println!("---------------ICMP Header---------------");
        println!("type: {}", self.r#type);
        println!("code: {}", self.code);
        println!("checksum: 0x{:04x}", u16::from_be(self.checksum));

        unsafe {
            if self.r#type == ICMP_ECHO_REQUEST || self.r#type == ICMP_ECHO_REPLY {
                // union field access is unsafe
                println!("id: {}", u16::from_be(self.ext.echo.id));
                println!("sequence: {}", u16::from_be(self.ext.echo.sequence));
            }
        }
        println!("----------------------------------------");
    }
}

#[repr(C, packed)]
pub union IcmpHdrExt {
    pub echo: IcmpEcho,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct IcmpEcho {
    pub id: u16,
    pub sequence: u16,
}
