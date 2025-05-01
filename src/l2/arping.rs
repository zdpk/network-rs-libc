use crate::util::socket_guard::SocketGuard;

use super::{if_arp::ArpHdr, if_ether::EthHdr};

pub fn arping(dest_ip: [u8; 4]) -> anyhow::Result<()> {
    let sock_fd = open_raw_socket()?;
    let _sg = SocketGuard(sock_fd);

    let iface = default_net::get_default_interface()
        .map_err(|e| anyhow::anyhow!("Failed to get default interface: {}", e))?;

    println!("Interface: {:?}", iface);
    // let if_index = get_if_index(&iface.name)?;
    bind_socket(sock_fd, iface.index as i32)?;

    let src_mac = iface.mac_addr.expect("Failed to get mac address").octets();
    let src_ip = iface.ipv4[0].addr.octets();
    send_arp_request(sock_fd, src_mac, src_ip, dest_ip, iface.index as i32)?;

    recv_arp_reply(sock_fd)?;

    Ok(())
}

fn open_raw_socket() -> anyhow::Result<i32> {
    let sock_fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, libc::ETH_P_ARP.to_be()) };
    if sock_fd < 0 {
        anyhow::bail!("Failed to create socket");
    }
    Ok(sock_fd)
}

fn get_if_index(if_name: &str) -> anyhow::Result<i32> {
    let if_name_cstr = std::ffi::CString::new(if_name)?;
    let if_index = unsafe { libc::if_nametoindex(if_name_cstr.as_ptr()) };
    if if_index == 0 {
        anyhow::bail!("Failed to get interface index");
    }
    Ok(if_index as i32)
}

fn send_arp_request(
    sock_fd: i32,
    src_mac: [u8; libc::ETH_ALEN as usize],
    src_ip: [u8; 4],
    dest_ip: [u8; 4],
    if_index: i32,
) -> anyhow::Result<()> {
    let mut buf = [0u8; libc::ETH_HLEN as usize + 28];
    let buf_ptr = buf.as_ptr() as *const libc::c_void;
    let buf_len = buf.len();
    let (eth_hdr, arp_hdr) = buf.split_at_mut(libc::ETH_HLEN as usize);

    let eth_hdr = init_eth_hdr(eth_hdr, src_mac);
    let arp_hdr = init_arp_hdr(arp_hdr, src_mac, src_ip, dest_ip);

    unsafe {
        // let mut addr: libc::sockaddr_ll = std::mem::zeroed();
        // addr.sll_family = libc::AF_PACKET as u16;
        // addr.sll_ifindex = if_index;
        // addr.sll_protocol = (libc::ETH_P_ARP as u16).to_be();

        // let sent_bytes = libc::sendto(
        //     sock_fd,
        //     buf_ptr,
        //     buf_len,
        //     0,
        //     &addr as *const _ as *const libc::sockaddr,
        //     std::mem::size_of_val(&addr) as libc::socklen_t,
        // );
        let sent_bytes = libc::send(sock_fd, buf_ptr as *const libc::c_void, buf_len, 0);

        println!("-------------ARP Request-------------");
        eth_hdr.print();
        arp_hdr.print();
        println!("-------------------------------------\n\n");

        if sent_bytes < 0 {
            anyhow::bail!("Failed to send arp request");
        }
    }

    Ok(())
}

fn init_eth_hdr(eth_hdr: &mut [u8], src_mac: [u8; libc::ETH_ALEN as usize]) -> &EthHdr {
    let eth_hdr = EthHdr::new(
        eth_hdr
            .try_into()
            .expect("Failed to convert eth_hdr to [u8; 14]"),
    );
    eth_hdr.h_dest = [0xff; 6];
    eth_hdr.h_source = src_mac;
    eth_hdr.h_proto = (libc::ETH_P_ARP as u16).to_be();

    eth_hdr
}

fn init_arp_hdr(
    arp_hdr: &mut [u8],
    src_mac: [u8; libc::ETH_ALEN as usize],
    src_ip: [u8; 4],
    dest_ip: [u8; 4],
) -> &ArpHdr {
    let arp_hdr = ArpHdr::new(
        arp_hdr
            .try_into()
            .expect("Failed to convert arp_hdr to [u8; 28]"),
    );
    arp_hdr.arp_hrd = libc::ARPHRD_ETHER.to_be();
    arp_hdr.arp_pro = (libc::ETH_P_IP as u16).to_be();
    arp_hdr.arp_hln = libc::ETH_ALEN as u8;
    arp_hdr.arp_pln = 4;
    arp_hdr.arp_op = libc::ARPOP_REQUEST.to_be();
    arp_hdr.arp_sha = src_mac;
    arp_hdr.arp_sip = src_ip;
    arp_hdr.arp_tha = [0x00; libc::ETH_ALEN as usize];
    arp_hdr.arp_tip = dest_ip;

    arp_hdr
}

fn bind_socket(sock_fd: i32, if_index: i32) -> anyhow::Result<()> {
    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_ifindex = if_index;
    addr.sll_protocol = (libc::ETH_P_ARP as u16).to_be();

    unsafe {
        let bind_result = libc::bind(
            sock_fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of_val(&addr) as libc::socklen_t,
        );
        if bind_result < 0 {
            anyhow::bail!("Failed to bind socket");
        }
    }

    Ok(())
}

fn recv_arp_reply(sock_fd: i32) -> anyhow::Result<()> {
    let mut buf = [0u8; libc::ETH_HLEN as usize + 28];

    loop {
        unsafe {
            // let mut addr: libc::sockaddr_ll = std::mem::zeroed();
            // let mut addr_len = 0;

            // let recv_bytes = libc::recvfrom(
            //     sock_fd,
            //     buf.as_mut_ptr() as *mut libc::c_void,
            //     buf.len(),
            //     0,
            //     &mut addr as *mut _ as *mut libc::sockaddr,
            //     &mut addr_len,
            // );
            let recv_bytes =
                libc::recv(sock_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0);

            if recv_bytes < 0 {
                anyhow::bail!("Failed to receive arp reply");
            }

            let (eth_hdr, arp_hdr) = buf.split_at_mut(libc::ETH_HLEN as usize);
            let eth_hdr = EthHdr::new(eth_hdr.try_into().unwrap());
            let arp_hdr = ArpHdr::new(arp_hdr.try_into().unwrap());

            if arp_hdr.arp_op != libc::ARPOP_REPLY.to_be() {
                continue;
            }

            println!("-------------ARP Reply-------------");
            eth_hdr.print();
            arp_hdr.print();
            println!("-----------------------------------\n\n");

            return Ok(());
        }
    }
}
