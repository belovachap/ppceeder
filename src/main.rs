mod log; mod message; mod dns;

use hickory_server::authority::Catalog;
use hickory_proto::rr::LowerName;

use std::collections::HashSet;
use std::ffi::CString;
use crate::log::{get_logger, LogLevel};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tokio::task::JoinSet;

use hickory_proto::rr::Name;
use hickory_server::server::ServerFuture;

use crate::message::addr_payload::AddrPayload;
use crate::message::message::Message;
use crate::message::net_addr::NetAddr;
use crate::message::var_str::VarStr;
use crate::message::version_payload::VersionPayload;
use crate::dns::handler::SeederAuthority;

const MAX_MESSAGES: usize = 20;
const SEED_NODE: &str = "seed.peercoin-library.org";
const PEERCOIN_PORT: u16 = 9901;

static QUIT: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone)]
pub(crate) struct GoodNode {
    ip_address: String,
    last_contact: u64,
}

pub(crate) struct AppState {
    good_nodes: Mutex<Vec<GoodNode>>,
    seed_node_ip_addresses: Vec<String>,
    dns_requests_a: Arc<AtomicU64>,
    dns_requests_non_a: Arc<AtomicU64>,
}

impl AppState {
    fn new(seed_node_ip_addresses: Vec<String>, dns_requests_a: Arc<AtomicU64>, dns_requests_non_a: Arc<AtomicU64>) -> Self {
        AppState {
            good_nodes: Mutex::new(Vec::new()),
            seed_node_ip_addresses,
            dns_requests_a,
            dns_requests_non_a,
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


}

async fn write_version_message(
    stream: &mut TcpStream,
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
    let _ = tokio::time::timeout(Duration::from_secs(20), message.write(stream)).await;

    log_trace!("logger", "Exiting write_version_message()");
}

async fn read_version_message(stream: &mut TcpStream) -> Option<VersionPayload> {
    log_trace!("logger", "Entering read_version_message()");

    let message = match tokio::time::timeout(Duration::from_secs(20), Message::read(stream)).await {
        Ok(Ok(m)) => m,
        _ => {
            log_error!("logger", "Failed to read_message or timed out.");
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

async fn write_verack_message(stream: &mut TcpStream) {
    log_trace!("logger", "Entering write_verack_message()");
    let message = Message::new("verack", Vec::new());
    let _ = tokio::time::timeout(Duration::from_secs(20), message.write(stream)).await;
    log_trace!("logger", "Exiting write_verack_message()");
}

async fn write_getaddr_message(stream: &mut TcpStream) {
    log_trace!("logger", "Entering write_getaddr_message()");
    let message = Message::new("getaddr", Vec::new());
    let _ = tokio::time::timeout(Duration::from_secs(20), message.write(stream)).await;
    log_trace!("logger", "Exiting write_getaddr_message()");
}

async fn connect_to_node(ip_str: &str) -> Option<(TcpStream, SocketAddrV4, VersionPayload)> {
    log_trace!("logger", "Entering connect_to_node()");

    let dest = SocketAddrV4::new(
        ip_str.parse::<Ipv4Addr>().ok()?,
        PEERCOIN_PORT,
    );

    let mut stream = match tokio::time::timeout(
        Duration::from_secs(20),
        TcpStream::connect(&dest),
    ).await {
        Ok(Ok(s)) => s,
        _ => {
            log_debug!("logger", "Connection to {} timed out or failed.", ip_str);
            return None;
        }
    };

    log_debug!("logger", "Connected to node: {}", ip_str);

    let from = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
    write_version_message(&mut stream, dest, from).await;

    let version_payload = match read_version_message(&mut stream).await {
        Some(vp) => vp,
        None => {
            return None;
        }
    };

    write_verack_message(&mut stream).await;

    log_debug!(
        "logger",
        "Seed node {} reports height: {}",
        ip_str,
        version_payload.start_height
    );

    log_trace!("logger", "Exiting connect_to_node()");
    Some((stream, dest, version_payload))
}

async fn check_node_version(ip_str: &str) -> Option<VersionPayload> {
    log_trace!("logger", "Entering check_node_version()");

    let dest = SocketAddrV4::new(
        ip_str.parse::<Ipv4Addr>().ok()?,
        PEERCOIN_PORT,
    );

    let mut stream = match tokio::time::timeout(
        Duration::from_secs(20),
        TcpStream::connect(&dest),
    ).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };

    let from = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
    write_version_message(&mut stream, dest, from).await;

    let version_payload = read_version_message(&mut stream).await?;

    drop(stream);

    log_trace!("logger", "Exiting check_node_version()");
    Some(version_payload)
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

async fn process_seed_node_messages(
    stream: &mut TcpStream,
    seed_ip: &str,
) -> Vec<String> {
    log_trace!("logger", "Entering process_seed_node_messages()");

    let mut result = Vec::new();
    write_getaddr_message(stream).await;

    for _ in 0..MAX_MESSAGES {
        if QUIT.load(Ordering::Relaxed) {
            break;
        }

        let message = match tokio::time::timeout(Duration::from_secs(20), Message::read(stream)).await {
            Ok(Ok(m)) => m,
            _ => {
                log_warn!("logger", "Seed node connection lost or timed out, moving on.");
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

async fn check_nodes(state: &Arc<AppState>, node_list: &HashSet<String>, seed_height: i32) {
    log_trace!("logger", "Entering check_nodes()");

    let mut join_set = JoinSet::new();

    for address in node_list.iter() {
        let state_clone = Arc::clone(state);
        let address = address.clone();
        join_set.spawn(async move {
            if QUIT.load(Ordering::Relaxed) {
                return;
            }

            log_debug!("logger", "Checking node: {}...", address);
            let version_payload = match check_node_version(&address).await {
                Some(vp) => vp,
                None => {
                    log_debug!("logger", "Connection to node {} failed.", address);
                    return;
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
                state_clone.add_or_update_good_node(&address);
            } else {
                log_debug!(
                    "logger",
                    "Node {} has height {} < seed height {}. Rejecting.",
                    address,
                    version_payload.start_height,
                    seed_height
                );
            }
        });
    }

    while join_set.join_next().await.is_some() {}

    log_trace!("logger", "Exiting check_nodes()");
}

async fn seed_thread(state: Arc<AppState>) {
    log_trace!("logger", "Entering seed_thread()");

    while !QUIT.load(Ordering::Relaxed) {
        log_debug!("logger", "seed_thread() starting while loop...");

        let mut all_discovered: HashSet<String> = HashSet::new();
        let mut min_seed_height: i32 = 0;

        // Spawn concurrent tasks for each seed node
        let mut join_set = JoinSet::new();

        for seed_ip in &state.seed_node_ip_addresses {
            let seed_ip = seed_ip.clone();
            join_set.spawn(async move {
                if QUIT.load(Ordering::Relaxed) {
                    return (seed_ip, 0i32, Vec::new());
                }

                let connection = connect_to_node(&seed_ip).await;
                let (mut stream, _, version_payload) = match connection {
                    Some(c) => c,
                    None => {
                        log_error!("logger", "Could not connect to seed node {}", seed_ip);
                        return (seed_ip, 0i32, Vec::new());
                    }
                };

                let seed_height = version_payload.start_height;
                let discovered = process_seed_node_messages(&mut stream, &seed_ip).await;
                (seed_ip, seed_height, discovered)
            });
        }

        // Collect results from all concurrent seed node connections
        while let Some(result) = join_set.join_next().await {
            match result {
                Ok((_seed_ip, seed_height, discovered)) => {
                    if min_seed_height == 0 {
                        min_seed_height = seed_height;
                    } else if seed_height < min_seed_height {
                        min_seed_height = seed_height;
                    }
                    all_discovered.extend(discovered);
                }
                Err(e) => {
                    log_error!("logger", "Seed node task panicked: {}", e);
                }
            }
        }

        if !all_discovered.is_empty() {
            check_nodes(&state, &all_discovered, min_seed_height).await;
        }

        log_debug!("logger", "seed_thread() taking a 60 minute break...");
        for _ in 0..3600 {
            if QUIT.load(Ordering::Relaxed) {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    log_trace!("logger", "Exiting seed_thread()");
}

async fn dns_thread(state: Arc<AppState>, bind_address: String) {
    log_trace!("logger", "Entering dns_thread()");

    let origin_name = Name::from_ascii("seed.peercoin.net.")
        .expect("Invalid origin name");
    let origin = LowerName::from(origin_name);
    let authority = SeederAuthority::new(origin.clone(), Arc::clone(&state));

    let mut catalog = Catalog::new();
    catalog.upsert(origin, Box::new(Arc::new(authority)));
    let mut server = ServerFuture::new(catalog);

    let udp_bind = format!("{}:53", bind_address);
    let udp_socket = tokio::net::UdpSocket::bind(&udp_bind)
        .await
        .expect("Failed to bind UDP socket");
    server.register_socket(udp_socket);

    let tcp_bind = format!("{}:53", bind_address);
    let tcp_listener = tokio::net::TcpListener::bind(&tcp_bind)
        .await
        .expect("Failed to bind TCP listener");
    server.register_listener(tcp_listener, Duration::from_secs(30));

    log_info!("logger", "DNS server listening on port 53");

    let server_future = server.block_until_done();
    tokio::pin!(server_future);

    loop {
        if QUIT.load(Ordering::Relaxed) {
            break;
        }
        tokio::select! {
            _ = &mut server_future => break,
            _ = tokio::time::sleep(Duration::from_secs(1)) => {},
        }
    }

    log_trace!("logger", "Exiting dns_thread()");
}

async fn stats_thread(state: Arc<AppState>) {
    log_trace!("logger", "Entering stats_thread()");

    while !QUIT.load(Ordering::Relaxed) {
        let count = state.good_nodes.lock().unwrap().len();
        let dns_reqs_a = state.dns_requests_a.load(Ordering::Relaxed);
        let dns_reqs_non_a = state.dns_requests_non_a.load(Ordering::Relaxed);
        log_info!("logger", "Stats: {} good nodes, {} A record requests, {} non-A record requests", count, dns_reqs_a, dns_reqs_non_a);
        for _ in 0..60 {
            if QUIT.load(Ordering::Relaxed) {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    log_trace!("logger", "Exiting stats_thread()");
}

async fn evict_thread(state: Arc<AppState>) {
    log_trace!("logger", "Entering evict_thread()");

    while !QUIT.load(Ordering::Relaxed) {
        for _ in 0..60 {
            if QUIT.load(Ordering::Relaxed) {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
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
    eprintln!("Usage: {} -b <bind_address> [-l <level>]", prog);
    eprintln!("  -b <address>  Bind address for DNS server (required, e.g. 0.0.0.0)");
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

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut log_level = LogLevel::Trace;
    let mut bind_address: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        if args[i] == "-h" || args[i] == "--help" {
            print_usage(&args[0]);
            return;
        } else if args[i] == "-b" && i + 1 < args.len() {
            i += 1;
            bind_address = Some(args[i].clone());
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
        i += 1;
    }

    let bind_address = match bind_address {
        Some(addr) => addr,
        None => {
            eprintln!("Error: bind address is required. Use -b <address>");
            print_usage(&args[0]);
            return;
        }
    };

    // Set the log level
    get_logger().lock().unwrap().set_level(log_level);

    // Set up signal handler
    unsafe {
        libc::signal(libc::SIGINT, handle_control_c as *const () as libc::sighandler_t);
    }

    // Resolve seed nodes and connect
    let seed_node_ip_addresses = resolve_seed_nodes();

    let dns_requests_a = Arc::new(AtomicU64::new(0));
    let dns_requests_non_a = Arc::new(AtomicU64::new(0));
    let state = Arc::new(AppState::new(seed_node_ip_addresses, dns_requests_a, dns_requests_non_a));

    log_info!("logger", "Starting dns thread");
    let dns_state = Arc::clone(&state);
    let dns_handle = tokio::spawn(async move { dns_thread(dns_state, bind_address).await });

    log_info!("logger", "Starting seed thread");
    let seed_state = Arc::clone(&state);
    let seed_handle = tokio::spawn(async move { seed_thread(seed_state).await });

    log_info!("logger", "Starting stats thread");
    let stats_state = Arc::clone(&state);
    let stats_handle = tokio::spawn(async move { stats_thread(stats_state).await });

    log_info!("logger", "Starting evict thread");
    let evict_state = Arc::clone(&state);
    let evict_handle = tokio::spawn(async move { evict_thread(evict_state).await });

    let _ = seed_handle.await;
    log_info!("logger", "Seed thread rejoined the main thread");

    let _ = stats_handle.await;
    log_info!("logger", "Stats thread rejoined the main thread");

    let _ = evict_handle.await;
    log_info!("logger", "Evict thread rejoined the main thread");

    // The dns thread doesn't have a clean way to stop the dns server, so we
    // cancel it after the other threads rejoin.
    // In Rust we can't easily cancel a thread, so we just wait.
    // Alternatively, the dns server could check QUIT in its loop.
    let _ = dns_handle.await;
    log_info!("logger", "Dns thread rejoined the main thread");
}
