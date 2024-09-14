use std::fs::File;
use std::os::fd::AsRawFd;
use std::sync::mpsc::{RecvError, TryRecvError};
use std::sync::{mpsc, Arc};
use std::{env, process, slice};
use std::net::{Ipv4Addr, SocketAddrV4,UdpSocket};
use std::io::{Read, Write};
use std::str::FromStr;
use std::time::{Duration, SystemTime};
use blake3::Hash;
use core_affinity::CoreId;
use rainfall::batch::Payload;
use rainfall::merkle::{verify_merkle_proof, MerklePath};
use blst::min_pk::{SecretKey,PublicKey,Signature};
use rand::{RngCore,Rng};
use rainfall::recvmessage::RecvMessage;
use libc::*;
use std::thread::{self, JoinHandle};


const QUEUE_SIZE:usize = 128;
const VLEN:c_uint = 1024;
const BATCH_SIZE: u64 = 1<<16;
const SPEED: usize = 1<<18;
const BURST: usize = 100;
const SECOND: u64 = 1000000000;
const BUFSIZE: c_uint = 1<<10;
/*for simplification purposes */
const FAKE_ROOT: [u8;32] = [200, 117, 111, 57, 59, 197, 34, 95, 163, 98, 125, 151, 19, 45, 52, 158, 129, 137, 
                            95, 68, 115, 72, 118, 235, 175, 93, 230, 204, 31, 175, 122, 223];


fn generate_key_pair( ) -> (SecretKey,PublicKey) {
    let mut rng = rand::thread_rng();
    let mut ikm = [0u8;32];
    rng.fill_bytes(&mut ikm);

    let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
    let pk = sk.sk_to_pk();
    (sk,pk)
}

fn get_sks_from_file() -> Vec<SecretKey>{
    let mut sks: Vec<SecretKey> = Vec::with_capacity(2 * BATCH_SIZE as usize);
    let mut f = File::open("src/keys/sks").expect("Unable to open file");
    for i in 0..(2* BATCH_SIZE) {
        let mut buf = [0u8;32];
        f.read(&mut buf).expect("failed to read");
        match SecretKey::from_bytes(&buf) {
            Ok(sk) => sks.push(sk),
            Err(e) => println!("error: {:?}",e),
        }
    }
    sks
}

fn main(){

    let args: Vec<String> = env::args().skip(1).collect();
    let client_addr:SocketAddrV4 ;

    match args.len() {
        1 => { 
            let delim:Vec<&str> = args[0].split(":").collect();
            assert!(delim.len() == 2);
            let addr: Vec<u8> = delim[0].split(".").map(|x| FromStr::from_str(x).unwrap()).collect();
            assert!(addr.len() == 4);
            let port: u16 = FromStr::from_str(delim[1]).unwrap();
            client_addr = SocketAddrV4::new(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]), port);
        },
        _ => {
            println!("Not the right number of arguments");
            println!("Format is: x.x.x.x:port_number");
            process::exit(1);
        }
    }
    
    let socket = UdpSocket::bind(client_addr).expect("couldn't bind to address");
    println!("Binded to socket");

    let val: c_int =1;
    let mut ret: c_int = 0;
    
    let len = std::mem::size_of::<c_int>() as socklen_t;
    
    unsafe {
        ret = setsockopt(socket.as_raw_fd(), SOL_SOCKET, SO_REUSEPORT, &val as *const c_int as *mut c_void,  len);
        if ret != 0 {
            panic!("setsockopt");
        }
        
        let blen: c_int = 1 << 25;
        ret = setsockopt(socket.as_raw_fd(), SOL_SOCKET, SO_RCVBUF, &blen as *const c_int as *const c_void, std::mem::size_of::<c_int>() as socklen_t);
        if ret != 0 {
            panic!("setsockopt");
        }
    
        ret = setsockopt(socket.as_raw_fd(), SOL_SOCKET, SO_SNDBUF, &blen as *const c_int as *const c_void, std::mem::size_of::<c_int>() as socklen_t);
    
        if ret != 0{
            panic!("setsockopt");
        }
    
        ret = getsockopt(socket.as_raw_fd(), SOL_SOCKET, SO_RCVBUF, &val as *const c_int as *mut c_void, &len as *const u32 as *mut u32);
        if ret <0 {
            panic!("getsockopt");
        }
        println!("SO_RCVBUF = {val} bytes");
    }


    let (tx_worker,rx_worker) = mpsc::sync_channel::<(RecvMessage,i32)>(100);
    let (tx_receiver,rx_receiver) = mpsc::sync_channel::<RecvMessage>(100);

    let (tx_sender, rx_sender) = mpsc::sync_channel::<Vec<(Signature,u64)>>(100);


    let socket_wrapped = Arc::new(socket);
    let addr = sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_addr: in_addr { s_addr: u32::from_be_bytes([172, 31, 0, 83]).to_be() },
        sin_port: u16::to_be(10000),
        sin_zero:[0;8],
    };
    let sks = Arc::new(get_sks_from_file());
    let mut signed_fake_root: Vec<Signature> = Vec::with_capacity(sks.len());
    let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    for i in 0..sks.len(){
        let sig = sks[i].sign(&FAKE_ROOT, dst, &[]);
        signed_fake_root.push(sig);
    }

    let payloads: Vec<Vec<u8>> = (0..(2 *BATCH_SIZE))
        .map(|x| Payload::new(x,0,vec![0u8;128]))
        .map(|p| p.to_bytes())
        .collect();
    let p = Arc::new(payloads);
    
    
    let mut handles: Vec<JoinHandle<()>> = vec![];
    
    let sender_thread = thread::spawn({
        let socket_clone = Arc::clone(&socket_wrapped);
        let p_clone= Arc::clone(&p);
        move || {
            
            let mut msg = RecvMessage::new();
            
        
            /* for this demo, the broker will send also the 
            client id
             */
        
            let mut payload_slice = &p_clone[..];
        
            let mut sent: usize = 0;
            let start = SystemTime::now();
        
            while sent < 2 * BATCH_SIZE as usize { 
                let now = SystemTime::now();
                let elapsed = now.duration_since(start).unwrap();
                let elapsed_sec = elapsed.as_nanos() as f64 / SECOND as f64;
                let mut allowance = (SPEED as f64 * elapsed_sec) as usize;
                let leeway = allowance - sent;
        
        
                if leeway < BURST {
                    let cooldown = ((BURST - leeway) as f64 * SECOND as f64) / (SPEED as f64);
                    thread::sleep(Duration::from_nanos(cooldown as u64));
                }
        
                allowance = 2 * BATCH_SIZE as usize - sent;

                if allowance > BURST {
                    allowance = BURST;
                }
        
                let mut b = 0;
                while b < allowance {
                    let mut len = allowance - b;
                    if len > VLEN as usize {
                        len = VLEN as usize;
                    }
        
                    if len < payload_slice.len() {
                        let (head,tail) = payload_slice.split_at(len);
                        payload_slice = tail;
                        msg.fill_to_send(addr, head);
                    }else {
                        msg.fill_to_send(addr, payload_slice);
                    }
        
                    unsafe {
                        let send_retval = sendmmsg(socket_clone.as_raw_fd(), msg.msgs, len as c_uint, 0);
                        if send_retval == -1 {
                            panic!("sendmmsg");
                        }
                    }
                    
                    b += VLEN as usize; 
                    sent += len;        
                }
            }

            let mut count = 0;

            // loop {
            //     println!("hello");
            //     match rx_sender.recv() {
            //         Ok(vec) => {
                        
                        

            //         },
            //         Err(e) => println!("{e}"),
            //     }
            // }
        }
    });
    handles.push(sender_thread);

    let receiver_thread = thread::spawn({
        let socket_clone = Arc::clone(&socket_wrapped);
        move || {
            let mut msg_avail: Vec<RecvMessage> = Vec::with_capacity(QUEUE_SIZE);
            for i in 0..QUEUE_SIZE{
                msg_avail.push(RecvMessage::new());
            }
            unsafe {

                let ret = core_affinity::set_for_current(CoreId { id: 3});
                if ret {
                    let mut count = 0;
                    loop {
                        if let Some(avail) = msg_avail.pop() {
                            let retval = recvmmsg(socket_clone.as_raw_fd(), avail.msgs, VLEN, 0, std::ptr::null_mut());
                            if retval == -1 {
                                panic!("recvmmsg()");
                            }

                            count += retval;
                            println!("received: {count}");

                            tx_worker.send((avail,retval)).unwrap();
                        }

                        match rx_receiver.try_recv(){
                            Ok(msg) => msg_avail.push(msg),
                            Err(e) => {
                                if e != TryRecvError::Empty {
                                    println!(" {}",e);
                                }
                            }
                        }
                    }
                }
            }
        }
    });


    handles.push(receiver_thread);

    let worker_thread = thread::spawn({
        let p_clone = Arc::clone(&p);
        let sk_clone = Arc::clone(&sks);
        let socket_clone = Arc::clone(&socket_wrapped);
        move || {

            let mut msgg = RecvMessage::new();

            let mut first:bool = false;
            let mut count = 0;

            let ret = core_affinity::set_for_current(CoreId { id: 2});
            if ret {

                loop {
                    match rx_worker.try_recv() {
                        Ok((msg,retval)) => {
                            if !first {
                                println!("time we receive first packets client side: {:?}",SystemTime::now());
                                first = true;
                            }
                            let now: SystemTime = SystemTime::now();
                            let mut vec_sigs: Vec<(Signature,u64)> = Vec::with_capacity(retval as usize);
                            unsafe {
                                let bufs_slice = slice::from_raw_parts(msg.bufs as *mut [u8;BUFSIZE as usize], retval as usize);
                                for i in 0..retval as usize {
                                    let (p,client) = MerklePath::from_bytes(&bufs_slice[i]);
                                    let sig = signed_fake_root[client as usize];
                                    vec_sigs.push((sig,client));
                                }
                                eprintln!("elapsed to get sigz {:?}",now.elapsed().unwrap());
                                

                                let payloads: Vec<Vec<u8>> = vec_sigs.iter()
                                .map(|x| Payload::new(x.1, 0, Vec::from(x.0.serialize())))
                                .map(|x| x.to_bytes())
                                .collect();
                            
                                // msgg.fill_to_send(addr, &payloads);
                                
                                // let now1 = SystemTime::now();
                                // let send_retval = sendmmsg(socket_clone.as_raw_fd(), msgg.msgs, vec_sigs.len() as c_uint, 0);
                                // if send_retval == -1 {
                                //     panic!("sendmmsg");
                                // }
                                // eprintln!("time to serialized + fill + send{:?}",now1.elapsed().unwrap());
                                
                                
                                
                                let mut payload_slice = &payloads[..];
                                let mut sent: usize = 0;
                                let start = SystemTime::now();
                                
                                while sent < payloads.len() as usize { 
                                    let now = SystemTime::now();
                                    let elapsed = now.duration_since(start).unwrap();
                                    let elapsed_sec = elapsed.as_nanos() as f64 / SECOND as f64;
                                    let mut allowance = (SPEED as f64 * elapsed_sec) as usize;
                                    let leeway = allowance - sent;
                                    
                                    
                                    if leeway < BURST {
                                        let cooldown = ((BURST - leeway) as f64 * SECOND as f64) / (SPEED as f64);
                                        thread::sleep(Duration::from_nanos(cooldown as u64));
                                    }
                                    
                                    allowance = payloads.len() as usize - sent;
                                    
                                    if allowance > BURST {
                                        allowance = BURST;
                                    }
                                    
                                    let mut b = 0;
                                    while b < allowance {
                                        let mut len = allowance - b;
                                        if len > VLEN as usize {
                                            len = VLEN as usize;
                                        }
                                        
                                        if len < payload_slice.len() {
                                            let (head,tail) = payload_slice.split_at(len);
                                            payload_slice = tail;
                                            msgg.fill_to_send(addr, head);
                                        }else {
                                            msgg.fill_to_send(addr, payload_slice);
                                        }
                                        
                                        
                                        let send_retval = sendmmsg(socket_clone.as_raw_fd(), msgg.msgs, len as c_uint, 0);
                                        if send_retval == -1 {
                                            panic!("sendmmsg");
                                        }
                                        
                                        b += VLEN as usize; 
                                        sent += len;        
                                    }
                                }
                                count += sent;
                                println!("sent: {count}");
                                tx_receiver.send(msg).unwrap(); 
                            }
                        },
                        Err(e) => {
                            if e != TryRecvError::Empty {
                                println!("error: {}",e);
                            }

                        }
                    }

                }
            }
        }
        
    });
    handles.push(worker_thread);

    for handle in handles {
        handle.join().unwrap();
    }

}