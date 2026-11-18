mod log; mod message; mod dns;

use std::collections::HashSet;
use std::ffi::CString;
use crate::log::{get_logger, LogLevel};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::dns::protocol::{Addr, DnsOpt};
use crate::dns::server::dnsserver;
use crate::message::addr_payload::AddrPayload;
use crate::message::message::Message;
use crate::message::net_addr::NetAddr;
use crate::message::var_str::VarStr;
use crate::message::version_payload::VersionPayload;

const MAX_MESSAGES: usize = 20;
const SEED_NODE: &str = "seed.peercoin-library.org";
const PEERCOIN_PORT: u16 = 9901;

static QUIT: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone)]
struct GoodNode {
    ip_address: String,
    last_contact: u64,
}

struct AppState {
    good_nodes: Mutex<Vec<GoodNode>>,
    seed_node_ip_addresses: Vec<String>,
}

impl AppState {
    fn new(seed_node_ip_addresses: Vec<String>) -> Self {
        AppState {
            good_nodes: Mutex::new(Vec::new()),
            seed_node_ip_addresses,
        }
    }

    fn add_or_update_good_node(&self, ip_address: &str) {
        let mut nodes = self.good_nodes.lock().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        for node in nodes.iter_mut() {
            if node.ip_address == ip_address {
                node.last_contact = now;
                return;
            }
        }
        nodes.push(GoodNode {
            ip_address: ip_address.to_string(),
            last_contact: now,
        });
    }

    fn get_good_ip_list(&self, addrs: &mut Vec<Addr>, _max: usize, _ipv4: bool, _ipv6: bool) -> usize {
        let nodes = self.good_nodes.lock().unwrap();
        let mut i = 0;
        for node in nodes.iter() {
            if i >= _max {
                break;
            }
            if let Ok(ip) = node.ip_address.parse::<Ipv4Addr>() {
                let octets = ip.octets();
                addrs.push(Addr::V4(octets));
                i += 1;
            }
        }
        i
    }
}

fn write_version_message(
    stream: &mut std::net::TcpStream,
    to: SocketAddrV4,
    from: SocketAddrV4,
) {
    log_trace!("logger", "Entering write_version_message()");

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    log_debug!("logger", "now -> {}", now);

    let to_addr = to.ip().to_string();
    log_debug!("logger", "to addr -> {}", to_addr);
    let mut ip_bytes = [0u8; 16];
    if address_to_ip(&to_addr, &mut ip_bytes) != 0 {
        log_error!("logger", "Failed to convert to address to ip bytes.");
        log_trace!("logger", "Exiting write_version_message()");
        return;
    }
    let addr_recv = NetAddr::new(now, 1, ip_bytes, 0);

    let from_addr = from.ip().to_string();
    log_debug!("logger", "from addr -> {}", from_addr);
    if address_to_ip(&from_addr, &mut ip_bytes) != 0 {
        log_error!("logger", "Failed to convert from address to ip bytes.");
        log_trace!("logger", "Exiting write_version_message()");
        return;
    }
    let addr_from = NetAddr::new(now, 0, ip_bytes, 0);

    log_debug!("logger", "making version_payload bytes");
    let user_agent = VarStr::new("coin-seeder".to_string());
    let version_payload = VersionPayload::new(addr_recv, addr_from, user_agent);
    let payload = version_payload.serialize();
    let message = Message::new("version", payload);
    let _ = message.write(stream);

    log_trace!("logger", "Exiting write_version_message()");
}

fn read_version_message(stream: &mut std::net::TcpStream) -> Option<VersionPayload> {
    log_trace!("logger", "Entering read_version_message()");

    let message = match Message::read(stream) {
        Ok(m) => m,
        Err(_) => {
            log_error!("logger", "Failed to read_message.");
            log_trace!("logger", "Exiting read_version_message()");
            return None;
        }
    };

    let command = String::from_utf8_lossy(&message.command)
        .trim_end_matches('\0')
        .to_string();

    if command != "version" {
        log_error!("logger", "Message command was not \"version\".");
        log_trace!("logger", "Exiting read_version_message()");
        return None;
    }

    let (version_payload, _) = VersionPayload::parse(&message.payload);

    log_trace!("logger", "Exiting read_version_message()");
    Some(version_payload)
}

fn write_verack_message(stream: &mut std::net::TcpStream) {
    log_trace!("logger", "Entering write_verack_message()");
    let message = Message::new("verack", Vec::new());
    let _ = message.write(stream);
    log_trace!("logger", "Exiting write_verack_message()");
}

fn write_getaddr_message(stream: &mut std::net::TcpStream) {
    log_trace!("logger", "Entering write_getaddr_message()");
    let message = Message::new("getaddr", Vec::new());
    let _ = message.write(stream);
    log_trace!("logger", "Exiting write_getaddr_message()");
}

fn connect_to_node(ip_str: &str) -> Option<(std::net::TcpStream, SocketAddrV4, VersionPayload)> {
    log_trace!("logger", "Entering connect_to_node()");

    let dest = SocketAddrV4::new(
        ip_str.parse::<Ipv4Addr>().ok()?,
        PEERCOIN_PORT,
    );

    let mut stream = match std::net::TcpStream::connect_timeout(&SocketAddr::V4(dest), Duration::from_secs(5)) {
        Ok(s) => s,
        Err(_) => {
            log_debug!("logger", "Could not connect to node {}", ip_str);
            return None;
        }
    };

    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

    log_debug!("logger", "Connected to seed node: {}", ip_str);

    let from = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
    write_version_message(&mut stream, dest, from);

    let version_payload = match read_version_message(&mut stream) {
        Some(vp) => vp,
        None => {
            log_error!("logger", "Handshake failed with seed node {}", ip_str);
            return None;
        }
    };

    write_verack_message(&mut stream);

    log_debug!(
        "logger",
        "Seed node {} reports height: {}",
        ip_str,
        version_payload.start_height
    );

    log_trace!("logger", "Exiting connect_to_node()");
    Some((stream, dest, version_payload))
}

fn resolve_seed_nodes() -> Vec<String> {
    log_trace!("logger", "Entering resolve_seed_nodes()");

    let mut addresses = Vec::new();

    let hints = libc::addrinfo {
        ai_family: libc::AF_INET,
        ai_socktype: libc::SOCK_STREAM,
        ..unsafe { std::mem::zeroed() }
    };

    let mut result: *mut libc::addrinfo = std::ptr::null_mut();
    let c_seed_node = CString::new(SEED_NODE).unwrap();
    let error_number = unsafe { libc::getaddrinfo(c_seed_node.as_ptr(), std::ptr::null(), &hints, &mut result) };

    if error_number != 0 {
        let err_str = unsafe { std::ffi::CStr::from_ptr(libc::gai_strerror(error_number)) };
        log_error!("logger", "getaddrinfo() for {}: {}", SEED_NODE, err_str.to_string_lossy());
        return addresses;
    }

    let mut info = result;
    while !info.is_null() {
        let info_ref = unsafe { &*info };
        if info_ref.ai_family == libc::AF_INET {
            let sockaddr = unsafe { &*(info_ref.ai_addr as *const libc::sockaddr_in) };
            let ip = Ipv4Addr::from(u32::from_be(sockaddr.sin_addr.s_addr));
            let ip_str = ip.to_string();
            log_info!("logger", "Resolved seed node: {}", ip_str);
            addresses.push(ip_str);
        }
        info = unsafe { (*info).ai_next };
    }

    unsafe { libc::freeaddrinfo(result) };
    log_trace!("logger", "Exiting resolve_seed_nodes()");
    addresses
}

fn process_seed_node_messages(
    stream: &mut std::net::TcpStream,
    seed_ip: &str,
) -> Vec<String> {
    log_trace!("logger", "Entering process_seed_node_messages()");

    let mut result = Vec::new();
    write_getaddr_message(stream);

    for _ in 0..MAX_MESSAGES {
        if QUIT.load(Ordering::Relaxed) {
            break;
        }

        let message = match Message::read(stream) {
            Ok(m) => m,
            Err(_) => {
                log_warn!("logger", "Seed node connection lost, moving on.");
                break;
            }
        };

        let command = String::from_utf8_lossy(&message.command)
            .trim_end_matches('\0')
            .to_string();

        if command != "addr" {
            log_debug!("logger", "Got a {} message from seed node, dropping.", command);
            continue;
        }

        log_debug!("logger", "Got addr message from seed node.");
        let (addr_payload, _) = AddrPayload::parse(&message.payload);
        log_debug!("logger", "has {} addresses", addr_payload.count.value);

        for na in &addr_payload.addr_list {
            if QUIT.load(Ordering::Relaxed) {
                break;
            }
            if na.port != PEERCOIN_PORT {
                continue;
            }

            // Extract IPv4 from the last 4 bytes of the 16-byte IPv6-mapped address
            let ip_bytes = &na.ip[12..16];
            let ip = Ipv4Addr::from([ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]]);
            let address = ip.to_string();

            if address == "127.0.0.1" || address == "0.0.0.0" || address == seed_ip {
                continue;
            }

            result.push(address);
        }

        break;
    }

    log_trace!("logger", "Exiting process_seed_node_messages()");
    result
}

fn check_nodes(state: &Arc<AppState>, node_list: &HashSet<String>, seed_height: i32) {
    log_trace!("logger", "Entering check_nodes()");

    let num_threads = 128;

    let nodes: Vec<&String> = node_list.iter().collect();
    let chunk_size = (nodes.len() + num_threads - 1) / num_threads;

    std::thread::scope(|s| {
        for chunk in nodes.chunks(chunk_size) {
            let state_clone = Arc::clone(state);
            let chunk_owned: Vec<String> = chunk.iter().map(|s| s.to_string()).collect();
            s.spawn(move || {
                for address in &chunk_owned {
                    if QUIT.load(Ordering::Relaxed) {
                        break;
                    }

                    log_debug!("logger", "Checking node: {}...", address);
                    let check_conn = connect_to_node(address);
                    let (_, _, version_payload) = match check_conn {
                        Some(c) => c,
                        None => {
                            log_debug!("logger", "Connection to node {} failed.", address);
                            continue;
                        }
                    };

                    if version_payload.start_height >= seed_height {
                        log_debug!(
                            "logger",
                            "Node {} has height {} >= seed height {}. Adding to GOOD_NODES.",
                            address,
                            version_payload.start_height,
                            seed_height
                        );
                        state_clone.add_or_update_good_node(address);
                    } else {
                        log_debug!(
                            "logger",
                            "Node {} has height {} < seed height {}. Rejecting.",
                            address,
                            version_payload.start_height,
                            seed_height
                        );
                    }
                }
            });
        }
    });

    log_trace!("logger", "Exiting check_nodes()");
}

fn seed_thread(state: Arc<AppState>) {
    log_trace!("logger", "Entering seed_thread()");

    while !QUIT.load(Ordering::Relaxed) {
        log_debug!("logger", "seed_thread() starting while loop...");

        let mut all_discovered: HashSet<String> = HashSet::new();
        let mut max_seed_height: i32 = 0;

        for seed_ip in &state.seed_node_ip_addresses {
            if QUIT.load(Ordering::Relaxed) {
                break;
            }
            let connection = connect_to_node(seed_ip);
            let (mut stream, _, version_payload) = match connection {
                Some(c) => c,
                None => {
                    log_error!("logger", "Could not connect to seed node {}", seed_ip);
                    continue;
                }
            };

            let seed_height = version_payload.start_height;
            if seed_height > max_seed_height {
                max_seed_height = seed_height;
            }

            let discovered = process_seed_node_messages(&mut stream, seed_ip);
            all_discovered.extend(discovered);
        }

        if !all_discovered.is_empty() {
            check_nodes(&state, &all_discovered, max_seed_height);
        }

        log_debug!("logger", "seed_thread() taking a 60 minute break...");
        for _ in 0..3600 {
            if QUIT.load(Ordering::Relaxed) {
                break;
            }
            thread::sleep(Duration::from_secs(1));
        }
    }

    log_trace!("logger", "Exiting seed_thread()");
}

fn dns_thread(state: Arc<AppState>) {
    log_trace!("logger", "Entering dns_thread()");

    let state_clone = Arc::clone(&state);
    let cb = Box::new(move |_opt: &DnsOpt, addrs: &mut Vec<Addr>, ipv4: bool, ipv6: bool| -> usize {
        state_clone.get_good_ip_list(addrs, usize::MAX, ipv4, ipv6)
    });

    let mut dns_opt = DnsOpt {
        port: 53,
        datattl: 60,
        nsttl: 40000,
        host: "dot-net-ns.peercoin-library.org".to_string(),
        ns: "dot-not-seed.peercoin-library.org".to_string(),
        mbox: Some(String::new()),
        cb,
        n_requests: 0,
    };

    let _ = dnsserver(&mut dns_opt);

    log_trace!("logger", "Exiting dns_thread()");
}

fn stats_thread(state: Arc<AppState>) {
    log_trace!("logger", "Entering stats_thread()");

    while !QUIT.load(Ordering::Relaxed) {
        let count = state.good_nodes.lock().unwrap().len();
        log_info!("logger", "Stats: {} good nodes", count);
        for _ in 0..60 {
            if QUIT.load(Ordering::Relaxed) {
                break;
            }
            thread::sleep(Duration::from_secs(1));
        }
    }

    log_trace!("logger", "Exiting stats_thread()");
}

fn evict_thread(state: Arc<AppState>) {
    log_trace!("logger", "Entering evict_thread()");

    while !QUIT.load(Ordering::Relaxed) {
        for _ in 0..60 {
            if QUIT.load(Ordering::Relaxed) {
                break;
            }
            thread::sleep(Duration::from_secs(1));
        }

        let cutoff = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_sub(24 * 60 * 60);

        let evicted = {
            let mut nodes = state.good_nodes.lock().unwrap();
            let before = nodes.len();
            nodes.retain(|node| node.last_contact > cutoff);
            before - nodes.len()
        };

        if evicted > 0 {
            log_info!("logger", "Evicted {} stale node(s) from GOOD_NODES.", evicted);
        }
    }

    log_trace!("logger", "Exiting evict_thread()");
}

fn handle_control_c() {
    log_trace!("logger", "Entering handle_control_c()");
    log_info!("logger", "Shutting down");
    QUIT.store(true, Ordering::Relaxed);
    log_trace!("logger", "Exiting handle_control_c()");
}

fn parse_log_level(level_str: &str) -> Option<LogLevel> {
    match level_str.to_lowercase().as_str() {
        "trace" => Some(LogLevel::Trace),
        "debug" => Some(LogLevel::Debug),
        "info" => Some(LogLevel::Info),
        "warn" => Some(LogLevel::Warn),
        "error" => Some(LogLevel::Error),
        "fatal" => Some(LogLevel::Fatal),
        _ => None,
    }
}

fn print_usage(prog: &str) {
    eprintln!("Usage: {} [-l <level>]", prog);
    eprintln!("  -l <level>  Set log level: trace, debug, info, warn, error, fatal (default: trace)");
    eprintln!("  -h          Show this help message");
}

fn address_to_ip(address: &str, out: &mut [u8; 16]) -> i32 {
    if let Ok(ip) = address.parse::<Ipv4Addr>() {
        let octets = ip.octets();
        out[..10].fill(0);
        out[10] = 0xFF;
        out[11] = 0xFF;
        out[12..16].copy_from_slice(&octets);
        return 0;
    }
    -1
}

pub fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut log_level = LogLevel::Trace;

    let mut i = 1;
    while i < args.len() {
        if args[i] == "-h" || args[i] == "--help" {
            print_usage(&args[0]);
            return;
        } else if args[i] == "-l" && i + 1 < args.len() {
            i += 1;
            match parse_log_level(&args[i]) {
                Some(level) => { log_level = level; break; }
                None => {
                    eprintln!("Invalid log level: {}", args[i]);
                    print_usage(&args[0]);
                    return;
                }
            }
        } else {
            eprintln!("Unknown argument: {}", args[i]);
            print_usage(&args[0]);
            return;
        }
    }

    // Set the log level
    get_logger().lock().unwrap().set_level(log_level);

    // Set up signal handler
    unsafe {
        libc::signal(libc::SIGINT, handle_control_c as *const () as libc::sighandler_t);
    }

    // Resolve seed nodes and connect
    let seed_node_ip_addresses = resolve_seed_nodes();

    let state = Arc::new(AppState::new(seed_node_ip_addresses));

    log_info!("logger", "Starting dns thread");
    let dns_state = Arc::clone(&state);
    let dns_handle = thread::spawn(move || dns_thread(dns_state));

    log_info!("logger", "Starting seed thread");
    let seed_state = Arc::clone(&state);
    let seed_handle = thread::spawn(move || seed_thread(seed_state));

    log_info!("logger", "Starting stats thread");
    let stats_state = Arc::clone(&state);
    let stats_handle = thread::spawn(move || stats_thread(stats_state));

    log_info!("logger", "Starting evict thread");
    let evict_state = Arc::clone(&state);
    let evict_handle = thread::spawn(move || evict_thread(evict_state));

    let _ = seed_handle.join();
    log_info!("logger", "Seed thread rejoined the main thread");

    let _ = stats_handle.join();
    log_info!("logger", "Stats thread rejoined the main thread");

    let _ = evict_handle.join();
    log_info!("logger", "Evict thread rejoined the main thread");

    // The dns thread doesn't have a clean way to stop the dns server, so we
    // cancel it after the other threads rejoin.
    // In Rust we can't easily cancel a thread, so we just wait.
    // Alternatively, the dns server could check QUIT in its loop.
    let _ = dns_handle.join();
    log_info!("logger", "Dns thread rejoined the main thread");
}
