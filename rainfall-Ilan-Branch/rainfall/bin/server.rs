use core::slice;
use std::fmt::Debug;
use std::fs::File;
use std::sync::mpsc::TryRecvError;
use std::{env, path, process};
use blst::min_pk::{PublicKey, Signature};
use rainfall::merkle::MerklePath;
use std::net::{Ipv4Addr,SocketAddrV4,UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, MutexGuard, RwLock};
use std::time::{Duration,SystemTime, UNIX_EPOCH};
use std::thread::{self, JoinHandle};
use std::io::{self, Read, Write};
use blake3::Hash;
use core_affinity::CoreId;

use libc::*;
use std::os::fd::AsRawFd;

use std::str::FromStr;

use rainfall::batch::{self, BatchConstruction, BatchManager, BatchProposal, BatchType, DistilledBatch, Payload};
use rainfall::recvmessage::RecvMessage;

/* Networking part */
const QUEUE_SIZE: usize = 100;
const VLEN:c_uint = 1024;
const BUFSIZE: c_uint = 1024;
const TIMEOUT_DURATION:u64 = 1;
const BATCH_SIZE:u64 =1<<16;



#[derive(Clone, Copy)]
enum ClientState {
    NotAssignedToBatch,
    AssignedToBatch(usize,usize),
    WaitingForSignature(u8),
}


fn get_pks_from_file() -> Vec<PublicKey>{
    let mut pks: Vec<PublicKey> = Vec::with_capacity(2 * BATCH_SIZE as usize);
    let mut f = File::open("src/keys/pks").expect("Unable to open file");
    for i in 0..(2* BATCH_SIZE) {
        let mut buf = [0u8;48];
        f.read(&mut buf).expect("failed to read");
        match PublicKey::from_bytes(&buf) {
            Ok(pk) => pks.push(pk),
            Err(e) => handle_error(e),
        }
    }
    pks
}


fn handle_error<E>(e: E) where E: Debug {
    println!("error handler: {:?}",e);
}


fn main(){

    let args: Vec<String>= env::args().skip(1).collect();
    let server_addr;

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

    /* Binding the socket and setting options*/
    let socket = UdpSocket::bind(server_addr).expect("couldn't bind to address");
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
    }
    
    let socket_wrapped = Arc::new(socket);

    let exec = Arc::new(AtomicBool::new(false));
    ctrlc::set_handler({
        let exp = Arc::clone(&exec);
        move || {
            exp.store(true,Ordering::Relaxed);
            std::process::exit(1);
        }}).expect("error setting Ctrl-C command");
        
    let (tx_receiver,rx_receiver) = mpsc::sync_channel::<RecvMessage>(QUEUE_SIZE);
    let (tx_worker_r,rx_worker_r) = mpsc::sync_channel::<(RecvMessage,i32)>(QUEUE_SIZE);
    let (tx_sender,rx_sender) = mpsc::sync_channel::<(RecvMessage,usize)>(QUEUE_SIZE);
    let (tx_worker_s, rx_worker_s) = mpsc::sync_channel::<RecvMessage>(QUEUE_SIZE);

    let pks = get_pks_from_file();
    println!("{}",pks.len());

    /*This fixed-size array tracks the batch assignement for each client.
    Each client is identified by their numerical ID, which is the index of their 
    public key in the vector of pks.
    If a client is not yet assigned to a batch, the client is in the WaitingForPayload state.
    Once a client is assigned to a batch, the client is in the WaitingForSignature state.
    After successfully sending a batch to the server, the client then goes back to the WaitingForPayload state.
    */
    let mut batch_per_id = Arc::new(Mutex::new(vec![ClientState::NotAssignedToBatch;150000 as usize]));
    let mut list_payload = Arc::new(Mutex::new(Vec::<Payload>::new()));
    let mut batchmanager = BatchManager::new();
    
    let mut handles: Vec<JoinHandle<()>> = vec![];
    let timeout_duration = Duration::from_secs(TIMEOUT_DURATION);
    
    let receiver_thread = thread::spawn({
        let socket_clone = Arc::clone(&socket_wrapped);
        move || {
            let mut msg_avail: Vec<RecvMessage>= Vec::with_capacity(QUEUE_SIZE);
            for i in 0..QUEUE_SIZE{
                msg_avail.push(RecvMessage::new());
            }
            
            let ret = core_affinity::set_for_current(CoreId { id: 3});
            if ret {
                
                unsafe {
                    println!("PID of receiver thread: {}",gettid());
                    let mut count: i32 = 0;
                    loop {
                        if exec.load(Ordering::Relaxed){
                            break;
                        }

                        if let Some(avail) = msg_avail.pop() {
                            let retval = recvmmsg(socket_clone.as_raw_fd(), avail.msgs, VLEN, 0, std::ptr::null_mut());
                            if retval == -1 {
                                panic!("recvmmsg()");
                            }
                            
                            // count += retval;
                            // println!("received {}",count);


                            match tx_worker_r.send((avail,retval)) {
                                Ok(_) => (),
                                Err(e) => handle_error(e),
                            }
                        }else {
                            println!("empty");
                        }
                        
                        if let Ok(msg) = rx_receiver.try_recv(){
                            msg_avail.push(msg);
                            
                        }
                    }
                }
            }
        }
    });
    handles.push(receiver_thread);
    
    
    let worker_thread = thread::spawn({
        let batches_clone = Arc::clone(&batch_per_id);
        move || {


            let ret = core_affinity::set_for_current(CoreId { id: 2});
            if ret {
                unsafe {
                    
                    let mut msg_avails: Vec<RecvMessage> = Vec::with_capacity(QUEUE_SIZE);
                    for i in 0..QUEUE_SIZE{
                        msg_avails.push(RecvMessage::new());
                    }
                    
                    let mut count: i32 = 0;
                    let mut total_received = 0;
                    loop {
    
                        if batchmanager.batches.is_empty() {
                            batchmanager.add_batch();
                        }

    
                        match rx_worker_r.recv() {
                            Ok((msg,num)) => {
                                /* */
                                let bufs_slice = slice::from_raw_parts(msg.bufs as *mut [u8;BUFSIZE as usize], VLEN as usize);
                                let addrs_slice = slice::from_raw_parts(msg.addrs as *mut sockaddr_in, VLEN as usize);
                                for i in 0..num as usize{
                                    let decoded_payload = Payload::from_bytes(&bufs_slice[i]);
                                    match decoded_payload {
                                        Ok(payload) => {
                                            let mut batch_per_id_locked = batches_clone.lock().unwrap();
                                            let client_id = payload.num_id;
                                            match batch_per_id_locked[client_id as usize] {
                                                ClientState::NotAssignedToBatch => {
                                                    let (batch_id,pos, addres_vec) = batchmanager.add_to_construction(addrs_slice[i], client_id, payload);
                                                    batch_per_id_locked[client_id as usize] = ClientState::AssignedToBatch(batch_id,pos);
                                                    if let Some((addrs,tree,clients)) = addres_vec {
                                                        println!("New batch was created, we should send the proofs of inclusions to the clients, client id {}",client_id);
                                                        
                                                        let mut paths: Vec<MerklePath> = Vec::new();
                                                        for i in &clients {
                                                            if let ClientState::AssignedToBatch(batch,pos) = batch_per_id_locked[*i as usize]{
                                                                paths.push(tree.find_merkle_path(pos));
                                                            }
                                                        }
                                                        
                                                        let mut slice_path = &paths[..];
                                                        let mut slice_addrs = &addrs[..];
                                                        let mut slice_clients = &clients[..];

                                                        assert!(slice_path.len() == slice_addrs.len() && slice_clients.len() == slice_path.len());
                                                        while slice_path.len() > VLEN as usize {
                                                            let (head_addr,tail_addr) = slice_addrs.split_at(VLEN as usize);
                                                            let (head_path,tail_path) = slice_path.split_at(VLEN as usize);
                                                            let (head_clients, tail_clients) = slice_clients.split_at(VLEN as usize);
                                                            slice_path = tail_path;
                                                            slice_addrs = tail_addr;
                                                            slice_clients = tail_clients;
                                                            let mut msg: RecvMessage = msg_avails.pop().unwrap();
                                                            msg.fill(head_addr, head_path,head_clients);
    
                                                            match tx_sender.send((msg,VLEN as usize)) {
                                                                Ok(_) => (),
                                                                Err(e) => handle_error(e),
                                                            }
    
                                                            match rx_worker_s.try_recv() {
                                                                Ok(msg) => msg_avails.push(msg),
                                                                Err(e) => {
                                                                    if e != TryRecvError::Empty {
                                                                       ();
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        
                                                        if slice_path.len() != 0 {
                                                            let mut msg: RecvMessage = msg_avails.pop().unwrap();
                                                            msg.fill(slice_addrs, slice_path,slice_clients);
                                                            match tx_sender.send((msg,slice_path.len())) {
                                                                Ok(_) => (),
                                                                Err(e) => (),
                                                            }
                                                        }

                                                        batchmanager.add_start_time(batch_id-1);
                                                    }
                                                },      
                                                ClientState::AssignedToBatch(batch_id,pos) => {

                                                    total_received+=1;
                                                    println!("total received: {}", total_received);
                                                    let pk = pks[client_id as usize];
                                                    let sig = Signature::deserialize(&payload.message)
                                                        .expect("failed to get signature from bytes");
                                                    batchmanager.add_to_proposal(batch_id,pos,client_id as usize,sig,pk,&mut count);
                                                    
                                                },
                                                ClientState::WaitingForSignature(batch_id) => (),
                                            }
                                        },
                                        Err(e) => handle_error(e),
                                    }
    
                                    match rx_worker_s.try_recv() {
                                        Ok(msg) => msg_avails.push(msg),
                                        Err(e) => {
                                            if e != TryRecvError::Empty {
                                                ()
                                            }
                                        }
                                    }
                                }
    
                                /*after will need to send a timeout or what not */
                                match tx_receiver.send(msg){
                                    Ok(_) => (),
                                    Err(e) => handle_error(e),
                                }
                            },
                            Err(e) => handle_error(e),
                        }
                    }
                }
            }
        }
    });
    handles.push(worker_thread);
    
    
    let sender_thread = thread::spawn({
        let socket_clone = Arc::clone(&socket_wrapped);
        move || {
            let ret = core_affinity::set_for_current(CoreId {id: 0});
            if ret {
                unsafe {
                    println!("PID of sender thread: {}",gettid());
                    let mut sent = 0;
                    loop {
                        match rx_sender.recv() {
                            Ok((msg,num)) => {
                                    let send_retval = sendmmsg(socket_clone.as_raw_fd(), msg.msgs, num as c_uint, 0);
                                    if send_retval == -1 {
                                        panic!("sendmmsg");
                                    }

                                    // sent += send_retval;
                                    // println!("sent {}",sent);

                                    tx_worker_s.send(msg).unwrap();
                            },
                            
                            Err(e) => handle_error(e),
                        }
                    }
                }
            }
            
        }
    });
    handles.push(sender_thread);    
    
    
    for handle in handles {
        handle.join().unwrap();
    }


    // let timeout_thread: JoinHandle<()> = thread::spawn({
    //     let clone_timeout: Arc<AtomicBool> = Arc::clone(&expired);
    //     let clone_start: Arc<Mutex<Option<SystemTime>>> = Arc::clone(&start_time);
    //     move || {
    //         loop {
    //             let now = SystemTime::now();
    //             match *clone_start.lock().unwrap() {
    //                 None => println!("The timer hasn't started yet. Waiting for connections"),
    //                 Some(time) => {
    //                     if now >= time + timeout_duration {
    //                         clone_timeout.store(true, Ordering::Relaxed);
    //                         println!("timer finished");
    //                         break;
    //                     }else{
    //                         let duration_since_unix = time.duration_since(UNIX_EPOCH).expect("TIME");
    //                         let remaining = now - duration_since_unix - timeout_duration;
    //                         println!("Time left: {:?}",remaining);
    //                     }
    //                 }
    //             }
    //         thread::sleep(Duration::from_secs(1));
    //         }
    //     }
    // });
}
        
    