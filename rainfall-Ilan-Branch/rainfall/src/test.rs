use crate::merkle::*;
use std::{collections::VecDeque};
use blake3::Hash;

#[cfg(test)]
mod tests {
    use std::path;

    use super::*;

    // #[test]
    // fn test_inclusion_different_nodes(){
    //     let deque= vec![&[1,2],&[3,4],&[5,6],&[7,8],"hello".as_bytes()];
    //     let tree: MerkleTree = MerkleTree::new(&deque);

    //     let path1 = tree.find_merkle_path(0);
    //     println!("{:?}",path1);
    //     let path2 = tree.find_merkle_path(1);
    //     let path3 = tree.find_merkle_path(2);
    //     let path4 = tree.find_merkle_path(3);

    //     assert_eq!(true,verify_merkle_proof(path1,&[1,2]));
    //     assert_eq!(true,verify_merkle_proof(path2,&[3,4]));
    //     assert_eq!(true,verify_merkle_proof(path3,&[5,6]));
    //     assert_eq!(true,verify_merkle_proof(path4,&[7,8]));
    // }


    #[test]
    #[should_panic]
    fn test_no_inclustion() {
        let deque= vec![&[1,2],&[3,4],&[5,6],&[7,8],"hello".as_bytes()];
        let tree: MerkleTree = MerkleTree::new(&deque);
        let path3 = tree.find_merkle_path(5);
    }

    #[test]
    fn test_build_merkle_odd_with_leftover(){

        let mut vec: Vec<&[u8]> = vec![&[1,2],&[3,4],&[5,6]];
        let mut hasher = blake3::Hasher::new();

        let leaf1 : &[u8] = &[1,2];
        let leaf2 : &[u8] = &[3,4];
        let leaf3 : &[u8] = &[5,6];

        let leaf1_hashed = blake3::hash(leaf1);   
        let leaf2_hashed = blake3::hash(leaf2);     
        let leaf3_hashed = blake3::hash(leaf3); 

        hasher.update(leaf1_hashed.as_bytes());
        hasher.update(leaf2_hashed.as_bytes());
        let parent12 = hasher.finalize();
        hasher.reset();

        hasher.update(parent12.as_bytes());
        hasher.update(leaf3_hashed.as_bytes());
        let root = hasher.finalize();
        
        let tree = MerkleTree::new(&vec);

        assert_eq!(root,tree.get_root_hash());
    
    }
}
