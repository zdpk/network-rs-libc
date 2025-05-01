use core::time;
use std::{
    process, thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
    l3::constant::{
        ICMP_ECHO_REQUEST, ICMP_HDR_MIN_LEN, ICMP_PAYLOAD_LEN, ICMP_TIMESTAMP_LEN, IP_DF,
        IP_HDR_MIN_LEN,
    },
    nic::interface::get_interface_by_name,
    util::{addr::fmt_ip, socket_guard::SocketGuard},
};

use super::{
    checksum::{calc_checksum, is_valid_icmp_checksum, is_valid_ip_checksum},
    icmp::{IcmpEcho, IcmpHdr, IcmpHdrExt, ICMP_NUM_PATTERN},
    ip::Ipv4Hdr,
};

pub fn ping(dest_ip: [u8; 4], if_name: &str) -> anyhow::Result<()> {
    let sock_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
    let _sg = SocketGuard(sock_fd);
    let interface = get_interface_by_name(if_name);
    // let interface = default_net::get_default_interface()
    //     .map_err(|e| anyhow::anyhow!("Failed to get default interface: {}", e))?;
    // let local_ip = interface.ipv4[0].addr.octets();
    let local_ip = interface.ip_addr;

    unsafe {
        libc::setsockopt(
            sock_fd,
            libc::IPPROTO_IP,
            libc::IP_HDRINCL,
            &1 as *const _ as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        );
    }
    if sock_fd < 0 {
        anyhow::bail!("Failed to create socket");
    }
    // bind_socket(sock_fd, local_ip)?;

    let mut dest_addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    dest_addr.sin_family = libc::AF_INET as u16;
    dest_addr.sin_port = 0;
    dest_addr.sin_addr.s_addr = u32::from_be_bytes(dest_ip);
    println!("sin_addr.s_addr: {}", dest_addr.sin_addr.s_addr);

    let mut sequence = 1u16;
    let max_sequence = 1;

    while sequence <= max_sequence {
        let id = sequence - 1;
        send_icmp_echo_request(sock_fd, dest_addr, sequence, id, local_ip, dest_ip)?;
        recv_icmp_echo_reply(sock_fd, sequence, id)?;
        sequence += 1;
        thread::sleep(Duration::from_secs(1));
    }

    Ok(())
}

fn bind_socket(sock_fd: i32, local_ip: [u8; 4]) -> anyhow::Result<()> {
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    addr.sin_family = libc::AF_INET as u16;
    // L3 does not need to specify port
    addr.sin_port = 0;
    addr.sin_addr.s_addr = u32::from_ne_bytes(local_ip);

    let bind_result = unsafe {
        libc::bind(
            sock_fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if bind_result < 0 {
        anyhow::bail!("Failed to bind socket");
    }

    Ok(())
}

fn send_icmp_echo_request(
    sock_fd: i32,
    dest_addr: libc::sockaddr_in,
    sequence: u16,
    id: u16,
    src_ip: [u8; 4],
    dest_ip: [u8; 4],
) -> anyhow::Result<()> {
    let sequence = sequence.to_be();

    let mut buf = [0u8; IP_HDR_MIN_LEN + ICMP_HDR_MIN_LEN + ICMP_PAYLOAD_LEN];
    let mut buf_len = buf.len();

    let (ip_hdr, icmp_hdr) = buf.split_at_mut(IP_HDR_MIN_LEN);
    let (icmp_hdr, icmp_data) = icmp_hdr.split_at_mut(ICMP_HDR_MIN_LEN);
    let (timestamp, num_pat) = icmp_data.split_at_mut(ICMP_TIMESTAMP_LEN);

    let icmp_hdr = IcmpHdr::new(icmp_hdr);
    icmp_hdr.r#type = ICMP_ECHO_REQUEST;
    icmp_hdr.code = 0;
    icmp_hdr.checksum = 0;
    icmp_hdr.ext = IcmpHdrExt {
        echo: IcmpEcho {
            id: (process::id() as u16).to_be(),
            sequence,
        },
    };
    // let duration = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    // let secs = duration.as_secs() as u32;
    // let nanos = duration.subsec_nanos();
    //
    // timestamp is no need to be big endian
    //
    let secs = duration.as_secs();
    let micros = duration.subsec_micros() as u64;
    println!("timestamp len: {}", timestamp.len());
    println!("num pat len: {}", num_pat.len());
    timestamp[..8].copy_from_slice(&secs.to_ne_bytes());
    timestamp[8..].copy_from_slice(&micros.to_ne_bytes());
    num_pat.copy_from_slice(&ICMP_NUM_PATTERN);
    icmp_hdr.checksum = calc_checksum(icmp_hdr, ICMP_HDR_MIN_LEN + ICMP_PAYLOAD_LEN).to_be();

    let ip_hdr = Ipv4Hdr::new(ip_hdr);
    ip_hdr.version_ihl = 4 << 4;
    ip_hdr.version_ihl |= 5;
    ip_hdr.tos = 0;
    ip_hdr.tot_len = (buf_len as u16).to_be();
    ip_hdr.id = id.to_be();
    ip_hdr.frag_off = IP_DF.to_be();
    ip_hdr.ttl = 64;
    ip_hdr.protocol = libc::IPPROTO_ICMP as u8;
    ip_hdr.check = 0;
    ip_hdr.check = calc_checksum(ip_hdr, buf_len);
    ip_hdr.saddr = u32::from_ne_bytes(src_ip);
    ip_hdr.daddr = u32::from_ne_bytes(dest_ip);

    ip_hdr.print_ip_hdr();
    icmp_hdr.print_icmp_hdr();
    println!("---------------ICMP Payload---------------");
    println!("icmp_data: {:02x?}", icmp_data);

    let sent_bytes = unsafe {
        libc::sendto(
            sock_fd,
            buf.as_ptr() as *const libc::c_void,
            buf_len,
            0,
            &dest_addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    println!("--------------------------------");
    if sent_bytes < 0 {
        anyhow::bail!("Failed to send ICMP echo request");
    }

    Ok(())
}

fn recv_icmp_echo_reply(sock_fd: i32, sequence: u16, id: u16) -> anyhow::Result<()> {
    let mut buf = [0u8; IP_HDR_MIN_LEN + ICMP_HDR_MIN_LEN + ICMP_PAYLOAD_LEN];
    let buf_len = buf.len();

    loop {
        let recv_bytes =
            unsafe { libc::recv(sock_fd, buf.as_ptr() as *mut libc::c_void, buf_len, 0) };
        if recv_bytes < 0 {
            anyhow::bail!("Failed to receive ICMP echo reply");
        }

        let (ip_hdr, icmp_hdr) = buf.split_at_mut(IP_HDR_MIN_LEN);
        let (icmp_hdr, icmp_data) = icmp_hdr.split_at_mut(ICMP_HDR_MIN_LEN);

        let ip_hdr = Ipv4Hdr::new(ip_hdr);
        let icmp_hdr = IcmpHdr::new(icmp_hdr);
        let (timestamp, num_pat) = icmp_data.split_at_mut(ICMP_TIMESTAMP_LEN);

        let seconds = u64::from_ne_bytes(timestamp[..8].try_into().unwrap());
        let microseconds = u64::from_ne_bytes(timestamp[8..].try_into().unwrap());
        println!("timestamp: {:02x?}", seconds.to_be_bytes());
        println!("microseconds: {:02x?}", microseconds.to_be_bytes());

        let timestamp = UNIX_EPOCH + Duration::new(seconds, (microseconds * 1000) as u32);
        println!("timestamp: {:?}", timestamp);

        let num_pat = num_pat.to_vec();
        println!("num_pat: {:02x?}", num_pat);
        //
        let icmp_len = u16::from_be(ip_hdr.tot_len) as usize - IP_HDR_MIN_LEN;
        println!("icmp_len: {}", icmp_len);

        unsafe {
            if u16::from_be(icmp_hdr.ext.echo.sequence) != sequence {
                println!("sequence is not match");
                continue;
            }

            if u16::from_be(icmp_hdr.ext.echo.id) != id {
                println!("id is not match");
                continue;
            }
        }

        if !is_valid_icmp_checksum(icmp_hdr, icmp_len as usize) {
            println!("icmp_hdr is invalid");
            continue;
        }
        if !is_valid_ip_checksum(ip_hdr) {
            println!("ip_hdr is invalid");
            continue;
        }
        ip_hdr.print_ip_hdr();
        icmp_hdr.print_icmp_hdr();
        println!("icmp_data: {:02x?}", icmp_data);

        return Ok(());
    }
}
