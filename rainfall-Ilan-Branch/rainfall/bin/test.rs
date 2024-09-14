use core_affinity::CoreId;
use libc::*;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool,Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;
use std::{cmp, env, mem, process, slice, thread};
use std::os::fd::AsRawFd;
use std::time::{Duration, SystemTime};
extern crate core_affinity;


const VLEN:c_uint = 1024;
const BUFSIZE: c_uint = 514;

fn main() {

    let args:Vec<String> = env::args().skip(1).collect();
    let mut server_addr:SocketAddrV4;

    match args.len() {
        1 => { 
            let delim:Vec<&str> = args[0].split(":").collect();
            assert!(delim.len() == 2);
            let addr: Vec<u8> = delim[0].split(".").map(|x| FromStr::from_str(x).unwrap()).collect();
            assert!(addr.len() == 4);
            let port: u16 = FromStr::from_str(delim[1]).unwrap();
            server_addr = SocketAddrV4::new(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]), port);
        },
        _ => {
            println!("Not the right number of arguments");
            println!("Format is: x.x.x.x:port_number");
            process::exit(1);
        }
    }


    let mut handles: Vec<JoinHandle<()>> = vec![];
    let num_threads =1;
    let mut ret: c_int = 0;

    println!("{}",server_addr);
    let socket = UdpSocket::bind(server_addr).expect("couldn't bind to address");
    let val: c_int =1;
    let len = std::mem::size_of::<c_int>() as socklen_t;
    
    ret = unsafe { setsockopt(socket.as_raw_fd(), SOL_SOCKET, SO_REUSEPORT, &val as *const c_int as *mut c_void,  len) };
    if ret != 0 {
        panic!("setsockopt");
    }

    let blen: c_int = 1 << 25;
    ret = unsafe {
        setsockopt(socket.as_raw_fd(), SOL_SOCKET, SO_RCVBUF, &blen as *const c_int as *const c_void, std::mem::size_of::<c_int>() as socklen_t)
    };
    if ret != 0{
        panic!("setsockopt");
    }

    ret = unsafe {
        setsockopt(socket.as_raw_fd(), SOL_SOCKET, SO_SNDBUF, &blen as *const c_int as *const c_void, std::mem::size_of::<c_int>() as socklen_t)
    };

    if ret != 0{
        panic!("setsockopt");
    }

    ret = unsafe { getsockopt(socket.as_raw_fd(), SOL_SOCKET, SO_RCVBUF, &val as *const c_int as *mut c_void, &len as *const u32 as *mut u32)};
    if ret <0 {
        panic!("getsockopt");
    }

    println!("SO_RCVBUF = {} bytes",val);


    let socket_server = Arc::new(socket);

    let total_received = Arc::new(Mutex::new(0));
    let total_sent =  Arc::new(Mutex::new(0));
    let packets_received = Arc::new(Mutex::new(0));
    let packets_sent = Arc::new(Mutex::new(0));

    let exec = Arc::new(AtomicBool::new(false));


    ctrlc::set_handler({
        let exp = Arc::clone(&exec);
        let real_clone = Arc::clone(&total_received);
        move || {
            exp.store(true,Ordering::Relaxed);
            println!("total received: {:?}",real_clone.lock().unwrap());
            println!("total sent: {:?}",real_clone.lock().unwrap());
            std::process::exit(1);
    }}).expect("error setting Ctrl-C command");



    #[derive(Clone,Debug)]
    struct RecvMessage { 
        msgs: *mut mmsghdr,
        iovecs: *mut iovec,
        addrs: *mut sockaddr_in,
        bufs: *mut [u8;VLEN as usize],
    }


    unsafe impl Send for RecvMessage {}
    unsafe impl Sync for RecvMessage {}


    let (tx,rx) = mpsc::sync_channel::<(RecvMessage,i32)>(2);
    let (tx_re,rx_re) = mpsc::sync_channel::<RecvMessage>(2);



    impl RecvMessage{
        fn new() -> Self{
            unsafe {
                let mut ret = 0;

                let mut memptr_msgs: *mut c_void = std::ptr::null_mut();
                let msgs_alignment: usize = std::mem::align_of::<mmsghdr>().next_power_of_two();

                ret = posix_memalign(&mut memptr_msgs, msgs_alignment * VLEN as usize, std::mem::size_of::<mmsghdr>() * VLEN as usize);  

                if ret != 0 {
                    libc::free(memptr_msgs);                
                    panic!("posix_memalign");
                }   
                /*initializing memory */
                libc::memset(memptr_msgs, 0, std::mem::size_of::<mmsghdr>() * VLEN as usize);
    
    
                let mut memptr_iovecs: *mut c_void = std::ptr::null_mut();
                let iovecs_alignment = std::mem::align_of::<iovec>().next_power_of_two();
                ret = posix_memalign(&mut memptr_iovecs, VLEN as usize * iovecs_alignment, std::mem::size_of::<iovec>() * VLEN as usize);
    
                if ret != 0{
                    libc::free(memptr_iovecs);
                    panic!("posix_memalign");
                };
                // /*initializing memory */
                libc::memset(memptr_iovecs, 0, std::mem::size_of::<iovec>() * VLEN as usize);
    
    

                let mut memptr_addrs: *mut c_void = std::ptr::null_mut();
                let addrs_alignment: usize = std::mem::align_of::<sockaddr_in>().next_power_of_two();
                ret = posix_memalign(&mut memptr_addrs, VLEN as usize * addrs_alignment, std::mem::size_of::<sockaddr_in>() * VLEN as usize);  
    
                if ret != 0{
                    libc::free(memptr_addrs);
                    panic!("posix_memalign");
                };
                /*initializing memory */
                libc::memset(memptr_addrs, 0, std::mem::size_of::<sockaddr_in>() * VLEN as usize);
    
    
                let mut memptr_bufs = std::ptr::null_mut();
                assert!(mem::size_of::<usize>().is_power_of_two());
                let bufs_alignment = cmp::max(mem::size_of::<usize>(), mem::size_of::<u8>() * VLEN as usize);
                ret = posix_memalign(&mut memptr_bufs, bufs_alignment, mem::size_of::<u8>() * VLEN as usize * (BUFSIZE +1) as usize);  

                if ret != 0{
                    libc::free(memptr_bufs);
                    panic!("posix_memalign");
                };
                // /*initializing memory */
                libc::memset(memptr_bufs, 0, std::mem::size_of::<u8>() * VLEN as usize * (BUFSIZE+1) as usize);
    
                assert!(!(memptr_iovecs as *mut iovec).is_null());
                assert!(!(memptr_msgs as *mut mmsghdr).is_null());
                assert!(!(memptr_addrs as *mut iovec).is_null());
                assert!(!(memptr_bufs as *mut [u8;VLEN as usize]).is_null());
                let iovec_slice = slice::from_raw_parts_mut(memptr_iovecs as *mut iovec, VLEN as usize);
                let msgs_slice = slice::from_raw_parts_mut(memptr_msgs as *mut mmsghdr, VLEN as usize);
                let addrs_slice = slice::from_raw_parts_mut(memptr_addrs as *mut sockaddr_in, VLEN as usize);
                let bufs_slice = slice::from_raw_parts_mut(memptr_bufs as *mut [u8;BUFSIZE as usize], VLEN as usize + 1);

                let addr = sockaddr_in {
                    sin_family: libc::AF_INET as u16,
                    sin_addr: in_addr { s_addr: u32::from_be_bytes([172, 31, 40, 133]).to_be() },
                    sin_port: u16::to_be(1234),
                    sin_zero:[0;8],
                };

                for i in 0..VLEN as usize {

                    iovec_slice[i].iov_base = bufs_slice[i].as_mut_ptr() as *mut c_void;
                    iovec_slice[i].iov_len = BUFSIZE as usize;
                    // addrs_slice[i] = addr;
                    msgs_slice[i].msg_hdr.msg_iov = &mut iovec_slice[i] as *mut _ as *mut iovec;
                    msgs_slice[i].msg_hdr.msg_iovlen = 1;
                    msgs_slice[i].msg_hdr.msg_name = &mut addrs_slice[i] as *mut _ as *mut c_void;
                    // msgs_slice[i].msg_hdr.msg_name = &addr as *const _ as *mut c_void;
                    msgs_slice[i].msg_hdr.msg_namelen =  mem::size_of::<sockaddr_in>() as u32;
                }

                Self{
                    msgs: memptr_msgs as *mut mmsghdr,
                    iovecs : memptr_iovecs as *mut iovec,
                    addrs: memptr_addrs as *mut sockaddr_in,
                    bufs: memptr_bufs as *mut [u8;VLEN as usize],
                }
            }
        }
    }

    impl Drop for RecvMessage {
        fn drop(&mut self) {
            unsafe {
                assert!(!self.addrs.is_null());
                libc::free(self.addrs as *mut c_void);

                assert!(!self.bufs.is_null());
                libc::free(self.bufs as *mut c_void);

                assert!(!self.iovecs.is_null());
                libc::free(self.iovecs as *mut c_void);

                assert!(!self.msgs.is_null());
                libc::free(self.msgs as *mut c_void);
            }
        }
    }


    // unsafe {
    //     println!("PID of main thread: {}",std::process::id());
    // }

    // let sender_thread = thread::spawn({
    //     let count_clone = Arc::clone(&total_sent);
    //     let socket_clone = Arc::clone(&socket_server);
    //     let expired = Arc::clone(&exec);

    //     move || {
    //         let res = core_affinity::set_for_current(CoreId {id: 2});
    //         if res {
    //             unsafe {
    //                 println!("PID of sender thread: {}",gettid());
    //             }
    //             let msg = RecvMessage::new(1234);
    //             loop {
    
    //                 if expired.load(Ordering::Relaxed){
    //                     break;
    //                 }
    
    //                 unsafe {
    //                     let send_retval = sendmmsg(socket_clone.as_raw_fd(),msg.msgs, VLEN as c_uint, 0);
    //                     if send_retval == -1 {
    //                         println!("error: {}",std::io::Error::last_os_error());
    //                         panic!("sendmmsg");
    //                     }
    
    //                     // let msgs_slice = slice::from_raw_parts(msg.msgs, VLEN as usize);
                            
    //                     // for i in 0..10 as usize{
    //                     //     println!("size of packets {}",msgs_slice[i].msg_len);
    //                     // }
    
    //                     let mut s = count_clone.lock().unwrap();
    //                     *s += send_retval;
    //                 }
    //             }
    //         }
    //     }
    // });

    // handles.push(sender_thread);


    let producer_thread = thread::spawn({
        let recv_clone = Arc::clone(&packets_received);
        let real_clone = Arc::clone(&total_received);
        let socket_clone = Arc::clone(&socket_server);
        let expired = Arc::clone(&exec);

        move || {

            /*EXPLICATION for magic number: 
            We would like to handle 84k clients sending a message per second. 
            But each interaction between the broker and one client consists of 2 messages sent by the client
            and two by the broker. In total, this results to 168 kpkts sent per second and 168 kpts received per second. 

            After testing on c6a.xlarge AWS instances (4 vCPUs and 8.0 GB of memory) both for the broker and
            the client (with clients sending ./udp c 172.31.42.245:8000 1000000 100000 100 1024 1:9000), 
            we found that a queue of size 2 is necessary to handle this packet rate. We also noted that reducing the burst parameter
            decreased packet loss
             */


            let queue_size = 2;
            let mut msg_avail: Vec<RecvMessage>= Vec::with_capacity(queue_size);
            for i in 0..queue_size{
                msg_avail.push(RecvMessage::new());
            }
            unsafe {
                println!("PID of receiver thread: {}",gettid());
            }

            loop {
                if expired.load(Ordering::Relaxed){
                    break;
                }

                    if let Some(avail) = msg_avail.pop() {
                        let retval = unsafe {recvmmsg(socket_clone.as_raw_fd(), avail.msgs, VLEN, 0, std::ptr::null_mut())};
                        if retval == -1 {
                            panic!("recvmmsg()");
                        }
                        // println!("time elapsed for receiving {:?}",now.elapsed());
                        
                        // let msgs_slice = slice::from_raw_parts_mut(avail.msgs, VLEN as usize);
                        
                        // for i in 0..retval as usize{
                        //     println!("size of packets {}",msgs_slice[i].msg_len);
                        // }

                        let mut recv = recv_clone.lock().unwrap();
                        *recv += retval; 
                        let mut total = real_clone.lock().unwrap();
                        *total += retval;


                
                        match tx.send((avail,retval)) {
                            Ok(_) => (),
                            Err(e) => break,
                        }
                    } else {
                        println!("queue is empty");
                    }
    
                    if msg_avail.len() < queue_size {
                        if let Ok(msg) = rx_re.try_recv(){
                            msg_avail.push(msg);
    
                        }
                    } 
                }
            }  
    });

    handles.push(producer_thread);

    
    let worker_thread = thread::spawn({
        let sent_clone = Arc::clone(&packets_sent);
        let socket_clone = Arc::clone(&socket_server);
        let expired = Arc::clone(&exec); 
        move || {

            let res = core_affinity::set_for_current(CoreId {id: 2});

            if res { 
                unsafe {
                    println!("PID of sender thread: {}",gettid());
                }
                
                loop {
    
                    if expired.load(Ordering::Relaxed) {
                        break;
                    }
    
                    //rsync -aAHXzcv ubuntu@... wd/
                    match rx.recv() {
                        Ok((msg,num)) => {
                            unsafe {
                                // let iovec_slice = slice::from_raw_parts_mut(msg.iovecs as *mut iovec, VLEN as usize);
                                // let msgs_slice = slice::from_raw_parts_mut(msg.msgs as *mut mmsghdr, VLEN as usize);
    
                                // let send_iovec_slice = slice::from_raw_parts_mut(send.iovecs as *mut iovec, VLEN as usize);
                                // let send_msgs_slice = slice::from_raw_parts_mut(send.msgs as *mut mmsghdr, VLEN as usize);
    
                                // for i in 0..num as usize{
                                //     send_msgs_slice[i].msg_hdr.msg_name = msgs_slice[i].msg_hdr.msg_name;
                                //     send_msgs_slice[i].msg_hdr.msg_namelen = msgs_slice[i].msg_hdr.msg_namelen;
                                // }
    
                                let send_retval = sendmmsg(socket_clone.as_raw_fd(), msg.msgs, num as c_uint, 0);
                                if send_retval == -1 {
                                    panic!("sendmmsg");
                                }
    
                                let mut send = sent_clone.lock().unwrap();
                                *send += send_retval;
                                
                                tx_re.send(msg).unwrap();
                            }
                        },
                        Err(e) => break,
                    }
                }
            }
        }
    });

    handles.push(worker_thread);




    let timer = thread::spawn({
        let recv_clone = Arc::clone(&packets_received);
        let send_clone = Arc::clone(&packets_sent);
        let expired = Arc::clone(&exec);
        let count= Arc::clone(&total_sent);

        move || {

            let res = core_affinity::set_for_current(CoreId {id: 3});
            if res {
                unsafe {
                    println!("PID of timer thread: {}",gettid());
                }
    
                let mut time: SystemTime = SystemTime::now();
                loop {
    
                    if expired.load(Ordering::Relaxed) {
                        break;
                    }
                    
                    if time.elapsed().unwrap() > Duration::from_secs(1){
                        let mut recv = recv_clone.lock().unwrap();
    
                        // let mut c = count.lock().unwrap();
                        let mut send = send_clone.lock().unwrap();
                        println!("packets received per second {} -- packets sent per second {}",recv,send);
                        *send = 0;
                        // println!("packets sent per second {}",c);
                        *recv = 0;
                        // *c = 0;
                        time = SystemTime::now();
    
                    }
    
                }
            }
        } 
    });

    handles.push(timer);

    for handle in handles{
        handle.join().unwrap();
    }

}

