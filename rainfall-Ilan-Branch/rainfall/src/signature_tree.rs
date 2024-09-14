use blst::min_pk::{AggregatePublicKey,AggregateSignature,Signature,PublicKey};
use std::collections::VecDeque;


const FAKE_ROOT: [u8;32] = [200, 117, 111, 57, 59, 197, 34, 95, 163, 98, 125, 151, 19, 45, 52, 158, 129, 137, 
                            95, 68, 115, 72, 118, 235, 175, 93, 230, 204, 31, 175, 122, 223];

#[derive(Debug)]
struct NodeT {
    tuple: (AggregateSignature,AggregatePublicKey),
    index: Option<usize>,
    left_child: Option<Box<NodeT>>,
    right_child: Option<Box<NodeT>>,
}

#[derive(Debug)]
pub struct SignatureTree {
    pub root: Option<NodeT>, 
}


impl NodeT {
    fn new(signature: AggregateSignature, pk:AggregatePublicKey,index:Option<usize>,left_child: Option<NodeT>,right_child: Option<NodeT>) -> Self {
        Self {
            tuple: (signature,pk),
            index,
            left_child : left_child.map(Box::new),
            right_child : right_child.map(Box::new),
        }
    }
}

impl SignatureTree{
    pub fn new(list_sigs: Vec<Signature>,list_pks: Vec<PublicKey>) -> Self {
        //for now let this as it is but more thorough checks must be done. 
        //the problem here is that the placeholder value used with the mem::replace is empty, but we will next implement a default trait
        // assert!(!list_sigs.is_empty());
        dbg!("length of sigs: {}",list_sigs.len());
        dbg!("length of pks: {}",list_pks.len());
        assert!(list_pks.len() == list_sigs.len());

        let mut tmp_sigs: VecDeque<NodeT> = list_sigs.into_iter()
            .enumerate()
            .zip(list_pks.into_iter())
            .map(|((idx,s),p)| NodeT::new(AggregateSignature::from_signature(&s),AggregatePublicKey::from_public_key(&p), Some(idx), None, None))
            .collect();


        while tmp_sigs.len() > 1 {
            let len = tmp_sigs.len()/2;
            for i in 0..len {
                let mut l1 = tmp_sigs.pop_front().unwrap();
                let l2 = tmp_sigs.pop_front().unwrap();
                l1.tuple.0.add_aggregate(&l2.tuple.0);
                l1.tuple.1.add_aggregate(&l2.tuple.1);
                tmp_sigs.push_back(NodeT::new(l1.tuple.0,l1.tuple.1,None,Some(l1),Some(l2)));
            }
        }

        Self {
            root: tmp_sigs.pop_back(),
        }
    }

    pub fn check(&self) -> Vec<usize> {
        
        let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
        let mut stack:Vec<&NodeT> = Vec::new();
        let root = self.root.as_ref().unwrap();
        stack.push(root);
        let mut fake_index: Vec<usize> = Vec::new();
        
        while !stack.is_empty() {
            let curr = stack.pop().expect("failed to unwrap");
            let sig = curr.tuple.0.to_signature();
            let pk = curr.tuple.1.to_public_key();
            match sig.verify(true, &FAKE_ROOT, dst, &[], &pk, true) {
                blst::BLST_ERROR::BLST_SUCCESS => (),
                blst::BLST_ERROR::BLST_VERIFY_FAIL => {
                    if curr.left_child.is_none() && curr.right_child.is_none() {
                        fake_index.push(curr.index.expect("the leaves of the tree have to have an index"));
                    }else {
                        stack.push(curr.right_child.as_ref().unwrap());
                        stack.push(curr.left_child.as_ref().unwrap());
                    }

                },
                e => println!("{:?}", e),
            }
        }
        fake_index
    }
}


/*For now useless  */

fn aggregate_keys_fast(list_pks: &[&PublicKey],lower:usize,upper:usize) -> PublicKey{
    let mut start = AggregatePublicKey::from_public_key(list_pks[lower]);
    for i in lower+1..=upper{
        start.add_aggregate(&AggregatePublicKey::from_public_key(list_pks[i]));
    }
    start.to_public_key()
}

fn aggregate_sigs_fast(list_sigs: &[&Signature],lower:usize,upper:usize) -> Signature{
    let mut start = AggregateSignature::from_signature(list_sigs[lower]);
    for i in lower+1..=upper {
        start.add_aggregate(&AggregateSignature::from_signature(list_sigs[i]));
    }
    start.to_signature()
}

