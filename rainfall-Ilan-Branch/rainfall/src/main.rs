use core::{hash, str};
use std::collections::VecDeque;
use std::hash::Hash;
use std::ops::Sub;
use std::str::FromStr;
use std::{env, mem, process};
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime};
use batch::Payload;
use blake3::*;
use blst::min_pk::{AggregatePublicKey, AggregateSignature, PublicKey, SecretKey, Signature};
use ctrlc;
use merkle::{Directions, MerklePath, MerkleTree};
use rand::{Rng,RngCore};
use crate::signature_tree::SignatureTree;
use crate::batch::BatchProposal;
use std::fs::File;
use std::io::{Read, Write};

mod batch;
mod merkle;
mod signature_tree;
mod recvmessage;
#[cfg(test)]
mod test;

const RATE_LIMITER_THRESHOLD: u32 = 100;
const BATCH_SIZE: usize = 1<<16;


/*buffers_pks is the file that all the brokers and servers have.
It contains the publics keys but not the associated private keys.
*/
// fn generate_key_pair() {
//     let mut buffer_pks: File = File::create("src/pks").expect("unable to create file");
//     let mut buffer_sks: File = File::create("src/sks").expect("unable to create file");
//     for i in 0..1<<17 {
//         let mut rng = rand::thread_rng();
//         let mut ikm = [0u8;32];
//         rng.fill_bytes(&mut ikm);
//         let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
//         let sk_bytes = sk.to_bytes();
//         let pk_bytes = sk.sk_to_pk().to_bytes();
//         buffer_pks.write_all(&pk_bytes).expect("failed to write public key");
//         buffer_sks.write_all(&sk_bytes).expect("failed to write secret key");
//     }
// }

fn get_pks() -> Vec<PublicKey> {
    let mut pks: Vec<PublicKey> = Vec::with_capacity(2*BATCH_SIZE);
    let mut f = File::open("src/pks").expect("Unable to open file");
    for i in 0..(2* BATCH_SIZE) {
        let mut buf = [0u8;48];
        f.read(&mut buf).expect("failed to read");
        match PublicKey::from_bytes(&buf) {
            Ok(pk) => pks.push(pk),
            Err(e) => println!("failed"),
        }
    }
    pks
}

fn fill() -> [u8;128]{
    let mut input = [0u8;128];
    let mut rng = rand::thread_rng();
    rng.fill(&mut input);
    input
}
fn main() {

    let hash = blake3::hash(b"ceciestunefausseracine");
    println!("{:?}",hash.as_bytes());

    // let lol = (0..1<<16).map(|x| Payload::new)




    // let mut input = [0u8;128];
    // let mut rng = rand::thread_rng();
    // rng.fill(&mut input);
    // let root = blake3::hash(&input);

    // let sk = PublicKey::no
    // let now = SystemTime::now();
    


    // let mut sigz: Vec<Signature> = Vec::new();
    // let mut pks: Vec<PublicKey> = Vec::new();
    // let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    
    // let key_pairs: Vec<(SecretKey,PublicKey)> = (0..BATCH_SIZE).map(|_| generate_key_pair()).collect();
    // for (sk,pk) in key_pairs {
    //     let sig = sk.sign(b"lol", dst, &[]);
    //     sigz.push(sig);
    //     pks.push(pk);
    // }

    
    // let malicious = generate_key_pair();
    // let malicious_sig = malicious.0.sign(b"CACA", dst, &[]);
    // sigz.push(malicious_sig);
    // pks.push(malicious.1);
    
    // generate_key_pair();
    // println!("{:?}",get_pks());
    // let sigs_borrow:Vec<&Signature> = sigz.iter().collect();
    // let pks_borrow:Vec<&PublicKey> = pks.iter().collect();
    // let res = binary_search(&pks_borrow[..], &sigs_borrow[..], b"messagetobesigned");
    // let tree = SignatureTree::new(&sigs_borrow, &pks_borrow);
    // let res = tree.check(b"lcaca");
    // let args: Vec<String> = env::args().skip(1).collect();
    // let mut server_addr: SocketAddrV4;
    // let mut client_addr: SocketAddrV4;


    // match args.len() {
    //     2 => {
    //         let delim_server: Vec<&str>= args[0].split(":").collect();
    //         assert!(delim_server.len() == 2);
    //         let s_addr:Vec<u8> = delim_server[0].split(".").map(|x| FromStr::from_str(x).unwrap()).collect();
    //         assert!(s_addr.len() == 4);
    //         let s_port:u16 = FromStr::from_str(delim_server[1]).unwrap();
    //         server_addr = SocketAddrV4::new(Ipv4Addr::new(s_addr[0], s_addr[1], s_addr[2], s_addr[3]),s_port);

    //         let c_addr:Vec<u8> = args[1].split(".").map(|x| FromStr::from_str(x).unwrap()).collect();
    //         assert!(c_addr.len() == 4);
    //         client_addr = SocketAddrV4::new(Ipv4Addr::new(c_addr[0], c_addr[1], c_addr[2], c_addr[3]),rand::thread_rng().gen_range(10000..65000));
    //     },
    //     _ => {
    //         println!("Not the right number of arguments");
    //         println!("Format is: x.x.x.x:port_number (SERVER ADDR) and y.y.y.y (CLIENT ADDR");
    //         process::exit(1);
    //     }
    // }

    // let mut handles:Vec<JoinHandle<()>> = vec![];
    // let real_total_sent = Arc::new(Mutex::new(0));
    // let total_sent = Arc::new(Mutex::new(0));
    // let sendz = Arc::new(Mutex::new(0));
    // let total_received = Arc::new(Mutex::new(0));
    // let socket: Arc<UdpSocket> = Arc::new(UdpSocket::bind(client_addr).expect("couldn't bind to address"));
    // socket.set_nonblocking(true).expect("failed to set to non blocking");

    // println!("connected to server");
    // let exec = Arc::new(AtomicBool::new(false));
    
    // let num_thread = 1;
    
    // ctrlc::set_handler({
    //     let exp = Arc::clone(&exec);
    //     let real_total = Arc::clone(&real_total_sent);
    //     move || {
    //         exp.store(true,Ordering::Relaxed);
    //         println!("total sent: {:?}",real_total.lock().unwrap());
    //         std::process::exit(1);
    // }}).expect("error setting Ctrl-C command");


    // let seconds_time = Arc::new(Mutex::new(SystemTime::now()));
    // let milis_time = Arc::new(Mutex::new(SystemTime::now()));

    // let time_thread = thread::spawn({
    //     // let recv_clone: Arc<Mutex<i32>> = Arc::clone(&total_received);
    //     // let sent_clone = Arc::clone(&total_sent);
    //     let seconds_clone = Arc::clone(&seconds_time);
    //     // let milis_clone = Arc::clone(&milis_time);
    //     let expired = Arc::clone(&exec);
    //     let hash = Arc::clone(&real_total_sent);
    //     // let sendz_clone = Arc::clone(&sendz);
    //     move || {
    //         let mut seconds = seconds_clone.lock().unwrap();
    //         // let mut milis = milis_clone.lock().unwrap();

    //         loop {

    //             if expired.load(Ordering::Relaxed) {
    //                 break;
    //             }

    //             // if milis.elapsed().unwrap() > Duration::from_millis(1) {
    //             //     let mut sendz = sendz_clone.lock().unwrap();
    //             //     *milis = SystemTime::now();
    //             //     *sendz = 0;
    //             // }

    //             if seconds.elapsed().unwrap() > Duration::from_secs(1) {
    //                 let mut hash_c = hash.lock().unwrap();
    //                 println!("hashed this much in second: {}",hash_c);
    //                 *hash_c = 0;
    //                 // let mut recv = recv_clone.lock().unwrap();
    //                 // let mut sent = sent_clone.lock().unwrap();
    //                 // println!("packets sent per second {} -- packets received per second {}",sent,recv);
    //                 *seconds = SystemTime::now();
    //                 // *recv = 0;
    //                 // *sent = 0;
    //             }

    //             thread::sleep(Duration::from_micros(1));
    //         }
    //     }
    // });
    // handles.push(time_thread);

    
    // let hash_thread = thread::spawn({
    //     let hashed = Arc::clone(&real_total_sent);
    //     let expired = Arc::clone(&exec);
    //     move || {
    //         let msg = b"sadjksjdvksjdvksaj;skdjva;skdjv ;aksjdv ;asjd ;asjd ";

    //         loop {

    //             if expired.load(Ordering::Relaxed){
    //                 break;
    //             }

    //             let h = blake3::hash(msg);
    //             let mut hashcount = hashed.lock().unwrap();
    //             *hashcount +=1;
    //         }
    //     }
    // });


    // for i in 0..num_thread {
    //     let recv_thread = thread::spawn({
    //         let recv_clone = Arc::clone(&total_received);
    //         let socket_clone = Arc::clone(&socket);
    //         let expired = Arc::clone(&exec);
    //         let time_clone = Arc::clone(&seconds_time);

    //         move || {
    //             loop {
    //                 if expired.load(Ordering::Relaxed) {
    //                     break;
    //                 }
    
    //                 let mut buf = [0;10];
    //                     match socket_clone.recv_from(&mut buf) {
    //                         Ok((received,addr)) => {
    //                             let mut recv = recv_clone.lock().unwrap();
    //                             *recv +=1;
    //                         },
    //                         Err(e) => (),
    //                     }
    //             }
    
    //         }
    //     });

    //     handles.push(recv_thread);
    // }

    // for i in 0..num_thread {
    //     let handle = thread::spawn({
    //         let socket_clone = Arc::clone(&socket);
    //         let sent_clone = Arc::clone(&total_sent);
    //         let real_clone = Arc::clone(&real_total_sent);
    //         let expired = Arc::clone(&exec);
    //         let sendz_clone = Arc::clone(&sendz);

    //         move|| {
    //             loop {

    //                 if expired.load(Ordering::Relaxed){
    //                     break;
    //                 }

    //                 let should_send = {
    //                     let sdz = sendz_clone.lock().unwrap();
    //                     *sdz < RATE_LIMITER_THRESHOLD
    //                 };

    //                 if should_send {
    //                     match socket_clone.send_to(b"hello",server_addr) {
    //                         Ok(size) => {
    //                             let mut sdz = sendz_clone.lock().unwrap();
    //                             let mut sent= sent_clone.lock().unwrap();
    //                             let mut real_sent = real_clone.lock().unwrap();
    //                             *sent +=1;
    //                             *sdz += 1;
    //                             *real_sent +=1;
    //                         },
    //                         Err(e) => println!("Error: {}",e),
    //                     }
    //                 } 
    //             }
    //         }
    //     });
    //     handles.push(handle);
    // }

    // for thread in handles {
    //     thread.join().unwrap();
    // }
    
}