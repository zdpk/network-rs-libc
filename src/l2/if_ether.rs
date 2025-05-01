use crate::util::addr::fmt_mac;

// https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_ether.h#L173
#[repr(C, packed)]
pub struct EthHdr {
    pub h_dest: [u8; libc::ETH_ALEN as usize],
    pub h_source: [u8; libc::ETH_ALEN as usize],
    pub h_proto: u16,
}

impl EthHdr {
    pub fn new(buf: &mut [u8; libc::ETH_HLEN as usize]) -> &mut Self {
        unsafe { &mut *(buf.as_mut_ptr() as *mut Self) }
    }

    pub fn print(&self) {
        println!("-----------Ethernet Header-------------");
        println!("Destination MAC: {}", fmt_mac(self.h_dest));
        println!("Source MAC: {}", fmt_mac(self.h_source));
        println!("Protocol: {}", fmt_proto(self.h_proto));
    }
}

fn fmt_proto(proto: u16) -> String {
    let proto_le = u16::from_be(proto);
    format!(
        "{}(0x{:04x})",
        match proto_le {
            0x0800 => "IPv4".to_string(),
            0x0806 => "ARP".to_string(),
            _ => "Unknown".to_string(),
        },
        proto_le
    )
}
