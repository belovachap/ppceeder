use std::io;
use std::os::unix::io::RawFd;

use libc::{
    c_int, c_void, in6addr_any, sockaddr_in6, socklen_t,
    AF_INET6, CMSG_FIRSTHDR, CMSG_NXTHDR, IPPROTO_IP, IP_PKTINFO,
    IPPROTO_UDP, SOCK_DGRAM,
};

use super::protocol::{dns_handle, DnsOpt};

const BUFLEN: usize = 512;

pub fn dnsserver(opt: &mut DnsOpt) -> io::Result<()> {
    log::trace!("Entering dnsserver()");

    // Create sender socket (unused in original but kept for parity)
    let _sender_socket = unsafe { socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP) };

    let listen_socket: RawFd = unsafe { socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP) };
    if listen_socket == -1 {
        log::error!("Could not create listen socket: -1");
        log::trace!("Exiting dnsserver()");
        return Err(io::Error::last_os_error());
    }

    // Enable IP_PKTINFO
    let sockopt: c_int = 1;
    unsafe {
        setsockopt(
            listen_socket,
            IPPROTO_IP,
            IP_PKTINFO,
            &sockopt as *const _ as *const c_void,
            std::mem::size_of::<c_int>() as socklen_t,
        );
    }

    // Bind
    let mut si6_me: sockaddr_in6 = unsafe { std::mem::zeroed() };
    si6_me.sin6_family = AF_INET6 as u16;
    si6_me.sin6_port = opt.port.to_be();
    si6_me.sin6_addr = unsafe { in6addr_any };

    let bind_ret = unsafe {
        bind(
            listen_socket,
            &si6_me as *const _ as *const libc::sockaddr,
            std::mem::size_of::<sockaddr_in6>() as socklen_t,
        )
    };
    if bind_ret == -1 {
        log::error!("Could not bind on listen socket: -2");
        log::trace!("Exiting dnsserver()");
        unsafe { close(listen_socket) };
        return Err(io::Error::last_os_error());
    }

    let mut inbuf = [0u8; BUFLEN];
    let mut si6_other: sockaddr_in6 = unsafe { std::mem::zeroed() };

    loop {
        // recvmsg with control data
        let mut iov = libc::iovec {
            iov_base: inbuf.as_mut_ptr() as *mut c_void,
            iov_len: BUFLEN,
        };

        let cmsg_size = unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::in_pktinfo>() as u32) } as usize;
        let mut cmsg_buf = vec![0u8; cmsg_size];

        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = &mut si6_other as *mut _ as *mut c_void;
        msg.msg_namelen = std::mem::size_of::<sockaddr_in6>() as socklen_t;
        msg.msg_iov = &mut iov as *mut _;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut c_void;
        msg.msg_controllen = cmsg_buf.len();

        let insize = unsafe { recvmsg(listen_socket, &mut msg, 0) };
        log::debug!("recvmsg() returned: {}", insize);
        if insize <= 0 {
            continue;
        }

        let insize = insize as usize;
        let ret = dns_handle(opt, &inbuf[..insize]);
        log::debug!("dnshandle() returned: {:?}", ret);

        let outbuf = match ret {
            Ok(buf) => buf,
            Err(e) => {
                // Build error response
                let mut err_buf = vec![0u8; 12];
                err_buf[0] = inbuf[0];
                err_buf[1] = inbuf[1];
                err_buf[2] = inbuf[2] | 128; // set QR
                err_buf[3] = inbuf[3] & !15 | (e as u8 & 0xF);
                err_buf
            }
        };

        let ret_len = outbuf.len();

        // Try to send via sendmsg with pktinfo
        let mut handled = false;
        let mut hdr = unsafe { CMSG_FIRSTHDR(&msg) };
        while !hdr.is_null() {
            let hdr_ref = unsafe { &*hdr };
            if hdr_ref.cmsg_level == IPPROTO_IP && hdr_ref.cmsg_type == IP_PKTINFO {
                // Build reply msghdr
                let mut reply_iov = libc::iovec {
                    iov_base: outbuf.as_ptr() as *mut c_void,
                    iov_len: ret_len,
                };
                let mut reply_msg: libc::msghdr = unsafe { std::mem::zeroed() };
                reply_msg.msg_name = &si6_other as *const _ as *mut c_void;
                reply_msg.msg_namelen = std::mem::size_of::<sockaddr_in6>() as socklen_t;
                reply_msg.msg_iov = &mut reply_iov as *mut _;
                reply_msg.msg_iovlen = 1;
                reply_msg.msg_control = cmsg_buf.as_mut_ptr() as *mut c_void;
                reply_msg.msg_controllen = cmsg_buf.len();

                unsafe {
                    sendmsg(listen_socket, &reply_msg, 0);
                }
                log::debug!("msg handled in loop");
                handled = true;
                break;
            }
            hdr = unsafe { CMSG_NXTHDR(&msg, hdr) };
        }

        if !handled {
            log::debug!("msg handled out of loop");
            unsafe {
                sendto(
                    listen_socket,
                    outbuf.as_ptr() as *const c_void,
                    ret_len,
                    0,
                    &si6_other as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<sockaddr_in6>() as socklen_t,
                );
            }
        }

        opt.n_requests += 1;
    }
}

// FFI wrappers for libc socket calls
extern "C" {
    fn socket(domain: c_int, typ: c_int, protocol: c_int) -> RawFd;
    fn bind(fd: RawFd, addr: *const libc::sockaddr, len: socklen_t) -> c_int;
    fn close(fd: RawFd) -> c_int;
    fn setsockopt(
        fd: RawFd,
        level: c_int,
        optname: c_int,
        optval: *const c_void,
        optlen: socklen_t,
    ) -> c_int;
    fn recvmsg(fd: RawFd, msg: *mut libc::msghdr, flags: c_int) -> isize;
    fn sendmsg(fd: RawFd, msg: *const libc::msghdr, flags: c_int) -> isize;
    fn sendto(
        fd: RawFd,
        buf: *const c_void,
        len: usize,
        flags: c_int,
        addr: *const libc::sockaddr,
        addrlen: socklen_t,
    ) -> isize;
}

