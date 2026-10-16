//! The router: the next hop of the route this computer would take to the internet.

use std::net::IpAddr;

/// The default gateway (IPv4), or `None` when there is no route to the internet.
#[cfg(windows)]
#[allow(unsafe_code)]
pub fn default_gateway() -> Option<IpAddr> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetBestRoute2, MIB_IPFORWARD_ROW2};
    use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_INET};
    // The route Windows would really use to reach the internet (metrics, VPNs and all).
    let mut destination = SOCKADDR_INET::default();
    // Plain C unions, written through their IPv4 view; 1.1.1.1 in network order.
    destination.Ipv4.sin_family = AF_INET;
    destination.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes([1, 1, 1, 1]);
    let mut route = MIB_IPFORWARD_ROW2::default();
    let mut source = SOCKADDR_INET::default();
    // SAFETY: valid pointers to initialised structures for the duration of the call.
    let status = unsafe {
        GetBestRoute2(
            std::ptr::null(),
            0,
            std::ptr::null(),
            &destination,
            0,
            &mut route,
            &mut source,
        )
    };
    if status != 0 {
        return None;
    }
    // SAFETY: the route's next hop is an IPv4 address for an IPv4 destination.
    let next = unsafe { route.NextHop.Ipv4.sin_addr.S_un.S_addr };
    let ip = std::net::Ipv4Addr::from(next.to_ne_bytes());
    // On-link routes (no gateway) have 0.0.0.0 as next hop.
    (!ip.is_unspecified()).then_some(IpAddr::V4(ip))
}

/// The default gateway, from the kernel routing table.
#[cfg(target_os = "linux")]
pub fn default_gateway() -> Option<IpAddr> {
    parse_proc_route(&std::fs::read_to_string("/proc/net/route").ok()?)
}

/// The default gateway, as reported by route(8).
#[cfg(target_os = "macos")]
pub fn default_gateway() -> Option<IpAddr> {
    let output = std::process::Command::new("/sbin/route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;
    parse_route_gateway(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub fn default_gateway() -> Option<IpAddr> {
    None
}

/// Default route of /proc/net/route: destination 00000000, gateway in little-endian hex,
/// the lowest metric first.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_proc_route(text: &str) -> Option<IpAddr> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.get(1) != Some(&"00000000") {
                return None;
            }
            let raw = u32::from_str_radix(fields.get(2)?, 16).ok()?;
            let metric: u32 = fields.get(6).and_then(|m| m.parse().ok()).unwrap_or(0);
            (raw != 0).then(|| {
                (
                    metric,
                    IpAddr::V4(std::net::Ipv4Addr::from(raw.swap_bytes())),
                )
            })
        })
        .min_by_key(|(metric, _)| *metric)
        .map(|(_, ip)| ip)
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn parse_route_gateway(text: &str) -> Option<IpAddr> {
    text.lines()
        .find_map(|line| line.trim().strip_prefix("gateway:")?.trim().parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_routes_pick_the_default_with_the_lowest_metric() {
        let text =
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
wlp2s0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0
bond0\t00000000\t0101A8C0\t0003\t0\t0\t300\t00000000\t0\t0\t0
bond0\t0001A8C0\t00000000\t0001\t0\t0\t300\t00FFFFFF\t0\t0\t0
";
        assert_eq!(parse_proc_route(text), Some("192.168.1.1".parse().unwrap()));
        assert_eq!(parse_proc_route("Iface\tDestination\n"), None);
    }

    #[test]
    fn macos_route_output() {
        let text = "   route to: default\ndestination: default\n       mask: default\n    gateway: 192.168.1.1\n  interface: en0\n";
        assert_eq!(
            parse_route_gateway(text),
            Some("192.168.1.1".parse().unwrap())
        );
        assert_eq!(
            parse_route_gateway("route: writing to routing socket: not in table"),
            None
        );
    }

    #[test]
    fn this_computer_has_a_router() {
        // The test machines are on a LAN; a gateway must be found.
        let gw = default_gateway();
        assert!(gw.is_some(), "no default gateway found");
    }
}
