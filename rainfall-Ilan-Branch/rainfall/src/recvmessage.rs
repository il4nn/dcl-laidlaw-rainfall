use libc::*;
use std::{cmp, mem::{self, MaybeUninit}, slice};

use crate::merkle::MerklePath;


const VLEN:c_uint = 1024;
const BUFSIZE: c_uint = 1024;


#[derive(Clone,Debug)]
pub struct RecvMessage { 
    pub msgs: *mut mmsghdr,
    pub iovecs: *mut iovec,
    pub addrs: *mut sockaddr_in,
    pub bufs: *mut [u8;BUFSIZE as usize],
}


unsafe impl Send for RecvMessage {}
unsafe impl Sync for RecvMessage {}

impl RecvMessage{
    pub fn new() -> Self{
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
            std::ptr::write_bytes(memptr_msgs, 0, std::mem::size_of::<mmsghdr>() * VLEN as usize);

            let mut memptr_iovecs: *mut c_void = std::ptr::null_mut();
            let iovecs_alignment = std::mem::align_of::<iovec>().next_power_of_two();
            ret = posix_memalign(&mut memptr_iovecs, VLEN as usize * iovecs_alignment, std::mem::size_of::<iovec>() * VLEN as usize);

            if ret != 0{
                libc::free(memptr_iovecs);
                panic!("posix_memalign");
            };
            // /*initializing memory */
            std::ptr::write_bytes(memptr_iovecs, 0, std::mem::size_of::<iovec>() * VLEN as usize);



            let mut memptr_addrs: *mut c_void = std::ptr::null_mut();
            let addrs_alignment: usize = std::mem::align_of::<sockaddr_in>().next_power_of_two();
            ret = posix_memalign(&mut memptr_addrs, VLEN as usize * addrs_alignment, std::mem::size_of::<sockaddr_in>() * VLEN as usize);  

            if ret != 0{
                libc::free(memptr_addrs);
                panic!("posix_memalign");
            };
            /*initializing memory */
            // libc::memset(memptr_addrs, 0, std::mem::size_of::<sockaddr_in>() * VLEN as usize);
            std::ptr::write_bytes(memptr_addrs, 0, std::mem::size_of::<sockaddr_in>() * VLEN as usize);


            let mut memptr_bufs = std::ptr::null_mut();
            assert!(mem::size_of::<usize>().is_power_of_two());
            let bufs_alignment = cmp::max(mem::size_of::<usize>(), mem::size_of::<u8>() * VLEN as usize);
            ret = posix_memalign(&mut memptr_bufs, bufs_alignment, mem::size_of::<u8>() * VLEN as usize * BUFSIZE as usize);  

            if ret != 0{
                libc::free(memptr_bufs);
                panic!("posix_memalign");
            };
            // /*initializing memory */
            // libc::memset(memptr_bufs, 0, std::mem::size_of::<u8>() * VLEN as usize * (BUFSIZE+1) as usize);
            std::ptr::write_bytes(memptr_bufs, 0, std::mem::size_of::<u8>() * VLEN as usize * BUFSIZE as usize);


            assert!(!(memptr_iovecs as *mut iovec).is_null());
            assert!(!(memptr_msgs as *mut mmsghdr).is_null());
            assert!(!(memptr_addrs as *mut iovec).is_null());
            assert!(!(memptr_bufs as *mut [u8;VLEN as usize]).is_null());
            let iovec_slice = slice::from_raw_parts_mut(memptr_iovecs as *mut iovec, VLEN as usize);
            let msgs_slice = slice::from_raw_parts_mut(memptr_msgs as *mut mmsghdr, VLEN as usize);
            let addrs_slice = slice::from_raw_parts_mut(memptr_addrs as *mut sockaddr_in, VLEN as usize);
            let bufs_slice = slice::from_raw_parts_mut(memptr_bufs as *mut [u8;BUFSIZE as usize], VLEN as usize);

            let addr = sockaddr_in {
                sin_family: libc::AF_INET as u16,
                sin_addr: in_addr { s_addr: u32::from_be_bytes([172, 31, 40, 133]).to_be() },
                sin_port: u16::to_be(1234),
                sin_zero:[0;8],
            };

            for i in 0..VLEN as usize {
                iovec_slice[i].iov_base = bufs_slice[i].as_mut_ptr() as *mut c_void;
                iovec_slice[i].iov_len = BUFSIZE as usize;
                msgs_slice[i].msg_hdr.msg_iov = &mut iovec_slice[i] as *mut _ as *mut iovec;
                msgs_slice[i].msg_hdr.msg_iovlen = 1;
                msgs_slice[i].msg_hdr.msg_name = &mut addrs_slice[i] as *mut _ as *mut c_void;
                msgs_slice[i].msg_hdr.msg_namelen =  mem::size_of::<sockaddr_in>() as u32;
            }

            Self{
                msgs: memptr_msgs as *mut mmsghdr,
                iovecs : memptr_iovecs as *mut iovec,
                addrs: memptr_addrs as *mut sockaddr_in,
                bufs: memptr_bufs as *mut [u8;BUFSIZE as usize],
            }
        }
    }


    pub fn fill(&mut self,addrs: &[sockaddr_in],paths: &[MerklePath],client_ids: &[u64]) {
        unsafe {

            assert!(!addrs.is_empty() && !paths.is_empty() && addrs.len() == paths.len());
            assert!(addrs.len() <= VLEN as usize);

            let length = addrs.len();
            let addrs_slice = slice::from_raw_parts_mut(self.addrs, length as usize);
            let bufs_slice = slice::from_raw_parts_mut(self.bufs,length as usize);

            for i in 0..length {
                let p = &paths[i];
                p.to_bytes(&mut bufs_slice[i][..BUFSIZE as usize],client_ids[i]);
                addrs_slice[i] = addrs[i];
            }
        }
    }


    pub fn fill_to_send(&mut self,addr: sockaddr_in,bytes: &[Vec<u8>]) {

        unsafe {
            assert!(!bytes.is_empty());

            let addrs_slice = slice::from_raw_parts_mut(self.addrs, bytes.len() as usize);
            let bufs_slice = slice::from_raw_parts_mut(self.bufs,bytes.len() as usize);

            for i in 0..bytes.len() {
                let b = &bytes[i][..];
                bufs_slice[i][..b.len()].copy_from_slice(&b);
                addrs_slice[i] = addr;
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