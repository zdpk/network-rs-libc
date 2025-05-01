use std::ffi::CString;

use crate::util::socket_guard::SocketGuard;

pub struct InterfaceBuilder {
    name: Option<String>,
    index: Option<u32>,
    mac_addr: Option<[u8; libc::ETH_ALEN as usize]>,
    ip_addr: Option<[u8; 4]>,
}

impl InterfaceBuilder {
    pub fn new() -> Self {
        Self {
            name: None,
            index: None,
            mac_addr: None,
            ip_addr: None,
        }
    }

    pub fn name(mut self, name: String) -> Self {
        self.name = Some(name);
        self
    }

    pub fn index(mut self, index: u32) -> Self {
        self.index = Some(index);
        self
    }

    pub fn mac_addr(mut self, mac_addr: [u8; libc::ETH_ALEN as usize]) -> Self {
        self.mac_addr = Some(mac_addr);
        self
    }

    pub fn ip_addr(mut self, ip_addr: [u8; 4]) -> Self {
        self.ip_addr = Some(ip_addr);
        self
    }

    pub fn build(self) -> Interface {
        Interface {
            name: self.name.unwrap(),
            index: self.index.unwrap(),
            mac_addr: self.mac_addr.unwrap(),
            ip_addr: self.ip_addr.unwrap(),
        }
    }
}

pub struct Interface {
    pub name: String,
    pub index: u32,
    pub mac_addr: [u8; libc::ETH_ALEN as usize],
    pub ip_addr: [u8; 4],
}

impl Interface {
    pub fn new(
        name: String,
        index: u32,
        mac_addr: [u8; libc::ETH_ALEN as usize],
        ip_addr: [u8; 4],
    ) -> Self {
        Self {
            name,
            index,
            mac_addr,
            ip_addr,
        }
    }
}

pub fn get_interface_by_name(if_name: &str) -> Interface {
    let if_name_cstr = CString::new(if_name).unwrap();
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    unsafe {
        std::ptr::copy_nonoverlapping(
            if_name_cstr.as_ptr(),
            ifr.ifr_name.as_mut_ptr(),
            std::cmp::min(if_name.len(), libc::IFNAMSIZ - 1),
        );
    }

    unsafe {
        let sock_fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if sock_fd < 0 {
            panic!("Failed to create socket");
        }
        let _sg = SocketGuard(sock_fd);

        // get interface index
        if libc::ioctl(sock_fd, libc::SIOCGIFINDEX, &mut ifr) < 0 {
            panic!("Failed to get interface index");
        }
        let if_index = ifr.ifr_ifru.ifru_ifindex as u32;
        println!("Interface index: {}", if_index);

        // notice - whenever `ioctl` is called, the previously got data is overwritten by other data
        if libc::ioctl(sock_fd, libc::SIOCGIFHWADDR, &mut ifr) < 0 {
            panic!("Failed to get interface hardware address");
        }
        let mut mac_addr = [0u8; libc::ETH_ALEN as usize];
        std::ptr::copy_nonoverlapping(
            ifr.ifr_ifru.ifru_hwaddr.sa_data.as_ptr(),
            mac_addr.as_mut_ptr(),
            mac_addr.len(),
        );
        println!("Interface hardware address: {:?}", mac_addr);

        if libc::ioctl(sock_fd, libc::SIOCGIFADDR, &mut ifr) < 0 {
            panic!("Failed to get interface IP address");
        }

        let mut ip_addr = [0u8; 4];
        std::ptr::copy_nonoverlapping(
            // ip addr length is 4, but sa_data is for both ip and mac so starts from 2(6-4)
            ifr.ifr_ifru.ifru_addr.sa_data.as_ptr().add(2),
            ip_addr.as_mut_ptr(),
            ip_addr.len(),
        );
        println!("Interface IP address: {:?}", ip_addr);

        Interface {
            name: if_name.to_string(),
            index: if_index,
            mac_addr,
            ip_addr,
        }
    }

    // let interface = Interface {

    // }

    // Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_interface_by_name() {
        let if_info = get_interface_by_name("eth0");
        // assert_eq!(if_info.name, "eth0");
        // assert_eq!(if_info.index, 2);
        // assert_eq!(if_info.mac_addr, [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // assert_eq!(if_info.ip_addr, [192, 168, 1, 100]);
    }
}
