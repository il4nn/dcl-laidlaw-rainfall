use core::fmt;
use std::{collections::VecDeque, path, time::SystemTime};
use bincode::Error;
use blake3::Hash;
use libc::SELFMAG;
use serde::{Serialize,Deserialize};

use crate::batch::Payload;

const BATCH_SIZE: usize = 1<<16;

/// Directions will be useful for MerkleProof
/// When we will reconstruct the root, we will need the 
/// directions to know in which order to concatenate the hashes
#[derive(Debug)]
#[derive(Clone, Copy)]
#[derive(serde::Serialize)]
#[derive(serde::Deserialize)]
pub enum Directions {
    Right,
    Left,
}

#[derive(Debug)]
struct NotADirection;

impl fmt::Display for NotADirection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Expected a bit (0 or 1) but got something else")
    }
}

impl Directions {
    fn to_bit(&self) -> u8{
        match self {
            Directions::Left => 0,
            Directions::Right => 1,
        }
    }

    fn from_bit(bit:u8) -> Result<Self,NotADirection>{
        match bit {
            0 => Ok(Directions::Left),
            1 => Ok(Directions::Right),
            _ => Err(NotADirection),
        }
    }
}


#[derive(Debug,Clone)]
pub struct MerkleTree {
    pub tree: Vec<Vec<Hash>>,
}

#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct MerklePath {
    pub path : Vec<(Hash,Directions)>,
}

impl MerklePath{
    pub fn new(path: Vec<(Hash,Directions)>) -> Self {
        Self {
            path,
        }   
    }

    /*Explanatation for why the buffer is a slice [u8:514].
    logbase2(65536) = 16. Each path will contain 16 hashes (hash of neighbours in merkle tree) and 
    16 directions (encoded on one bit), which indicate in which order to concatenate the hashes.
    Each hash is 32 bytes, so 16*32 = 512. The 16 directions can be encoded on two bytes. So 514 bytes.
    We need one last byte to encode the len of the path. 
    */
    pub fn to_bytes(&self,buf: &mut [u8],client_id: u64){
        assert!(buf.len() >= 515);

        let path_len = self.path.len() as u8;
    
        let hashes: Vec<&Hash>= self.path
            .iter()
            .map(|(h,d)| h)
            .collect();
    
        let dirs: Vec<&Directions>= self.path
            .iter()
            .map(|(h,d)| d)
            .collect();

        let serialized_dirs: Vec<u8> = dirs.chunks(8)
            .map(|c| c.to_vec())
            .map(|vec| directions_to_byte(vec))
            .collect();

        assert!(serialized_dirs.len() == 2);

        buf[0] = path_len;
        buf[1] = serialized_dirs[0];
        buf[2] = serialized_dirs[1];

        let mut start = 3;
        for hash in hashes {
            buf[start..start+32].copy_from_slice(hash.as_bytes());
            start+=32;
        }
        buf[start..start+8].copy_from_slice(&client_id.to_be_bytes());
    }


    pub fn from_bytes(buf: &[u8]) ->  (Self,u64) {
        assert!(!buf.is_empty());

        let path_len = buf[0] as usize;
        assert!(buf.len() >= 3 + path_len * 32);
        
        let mut path: Vec<(Hash,Directions)> = Vec::with_capacity(path_len);
        
        let mut directions = byte_to_direction(buf[1]);
        directions.extend(byte_to_direction(buf[2]));
        
        let paths = &buf[3..];
        for i in 0..path_len {
            let bytes: [u8;32] = paths[i*32..(i+1)*32].try_into().expect("slice incorrect length");
            let hash = blake3::Hash::from(bytes);
            path.push((hash,directions[i]));
        }
        
        let client_id = u64::from_be_bytes(paths[(path_len * 32)..(path_len*32)+8].try_into().expect("slice incorrect length"));
        (MerklePath { path }, client_id)
    }
}

impl MerkleTree { 

    
    /*TODO: need to check certain condition, removed the assert for 
    the placeholder value when changing states */
    pub fn new(leaves: &Vec<&[u8]>) -> Self{

        let hashed_leaves = leaves.iter().map(|x| blake3::hash(x)).collect();

        let mut tree: Vec<Vec<Hash>> = Vec::new();
        tree.push(hashed_leaves);

        while tree.last().unwrap().len() > 1 {
            let mut next_level = Vec::new();
            let current_level = tree.last().unwrap();

            for tuples in current_level.chunks(2) {
                if tuples.len() == 2 {
                    next_level.push(hash_concat(tuples[0], tuples[1]));
                } else {
                    next_level.push(tuples[0]);
                }
            }
            tree.push(next_level);
        }

        Self {
            tree,
        }
    }

    pub fn get_root_hash(&self) -> Hash {
        self.tree[self.tree.len()-1][0]
    }

    pub fn find_merkle_path(&self,target_index: usize) -> MerklePath {
        assert!(target_index < BATCH_SIZE);
        let mut path: Vec<(Hash,Directions)> = Vec::new();

        let mut idx = target_index;
        for level in 0..self.tree.len()-1 {
            let sibling_index = idx^1;
            if idx %2 == 0{
                path.push((self.tree[level][sibling_index as usize].clone(),Directions::Left));
            }else {
                path.push((self.tree[level][sibling_index as usize].clone(),Directions::Right));
            }
            idx /= 2;
        }

        MerklePath::new(path)
    }
}

pub fn verify_merkle_proof(merklepath: MerklePath, payload_sent: &[u8]) -> Hash {

    let mut recomputed_root: Hash = blake3::hash(payload_sent);
    for tuple in merklepath.path.iter(){
        match tuple.1 {
            Directions::Right => {
                recomputed_root = hash_concat(tuple.0, recomputed_root);
            },
            Directions::Left => {
                recomputed_root = hash_concat(recomputed_root, tuple.0);
            },
        }
    }
    recomputed_root 
}

fn hash_concat(left_hash: Hash, right_hash: Hash) -> Hash{
    let mut hasher = blake3::Hasher::new(); 
    hasher.update(left_hash.as_bytes());
    hasher.update(right_hash.as_bytes());
    hasher.finalize()
}


fn directions_to_byte(directions: Vec<&Directions>) -> u8 {
    assert!(directions.len() == 8);

    let mut byte = 0u8;
    for (idx,dir) in directions.iter().enumerate() {
        byte |= dir.to_bit() << idx; 
    }
    return byte
}

fn byte_to_direction(byte: u8) -> Vec<Directions> {
    let mut directions: Vec<Directions> = Vec::new();

    for i in 0..8 {
        let dir = Directions::from_bit((byte >> i) & 1);
        if let Ok(d) = dir {
            directions.push(d);
        }
    }

    directions
}