use network_ex::l2;

fn panic_usage() -> ! {
    panic!("Usage: arping <destination_ip>");
}

fn parse_args() -> [u8; 4] {
    let args = std::env::args().collect::<Vec<String>>();

    if args.len() != 2 {
        panic_usage();
    }

    let dest_ip = args[1].split('.').collect::<Vec<&str>>();

    if dest_ip.len() != 4 {
        panic_usage();
    }

    let dest_ip: [u8; 4] = dest_ip
        .iter()
        .map(|s| s.parse::<u8>().unwrap())
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();

    dest_ip
}

pub fn main() -> anyhow::Result<()> {
    let dest_ip = parse_args();

    l2::arping::arping(dest_ip)?;

    Ok(())
}
