use crate::util::addr::{fmt_ip, fmt_mac};

// https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_arp.h#L145
#[repr(C, packed)]
pub struct ArpHdr {
    // Hardware type
    pub arp_hrd: u16,
    // Protocol type
    pub arp_pro: u16,
    pub arp_hln: u8,
    pub arp_pln: u8,
    pub arp_op: u16,
    pub arp_sha: [u8; libc::ETH_ALEN as usize],
    pub arp_sip: [u8; 4],
    pub arp_tha: [u8; libc::ETH_ALEN as usize],
    pub arp_tip: [u8; 4],
}

impl ArpHdr {
    pub fn new(buf: &mut [u8; 28]) -> &mut Self {
        unsafe { &mut *(buf.as_mut_ptr() as *mut Self) }
    }

    pub fn print(&self) {
        println!("-----------ARP Header:-------------");
        println!("Hardware type: {}", fmt_arp_hrd(self.arp_hrd));
        println!("Protocol type: {}", fmt_arp_pro(self.arp_pro));
        println!("Hardware length: {}", self.arp_hln);
        println!("Protocol length: {}", self.arp_pln);
        println!("Operation: {}", fmt_arp_op(self.arp_op));
        println!("Sender MAC: {}", fmt_mac(self.arp_sha));
        println!("Sender IP: {}", fmt_ip(self.arp_sip));
        println!("Target MAC: {}", fmt_mac(self.arp_tha));
        println!("Target IP: {}", fmt_ip(self.arp_tip));
    }
}

fn fmt_arp_hrd(hrd: u16) -> String {
    let hrd_le = u16::from_be(hrd);
    format!(
        "{}(0x{:04x})",
        match hrd_le {
            1 => "Ethernet".to_string(),
            _ => "Unknown".to_string(),
        },
        hrd_le
    )
}

fn fmt_arp_pro(pro: u16) -> String {
    let pro_le = u16::from_be(pro);
    format!(
        "{}(0x{:04x})",
        match pro_le {
            0x0800 => "IPv4".to_string(),
            0x0806 => "ARP".to_string(),
            _ => "Unknown".to_string(),
        },
        pro_le
    )
}

fn fmt_arp_op(op: u16) -> String {
    let op_le = u16::from_be(op);
    format!(
        "{}(0x{:04x})",
        match op_le {
            1 => "ARP Request".to_string(),
            2 => "ARP Reply".to_string(),
            3 => "RARP Request".to_string(),
            4 => "RARP Reply".to_string(),
            _ => "Unknown".to_string(),
        },
        op_le
    )
}
