use std::{collections::VecDeque, sync::Arc, time::{Duration, SystemTime}};
use bincode::Options;
use blst::min_pk::{AggregatePublicKey, AggregateSignature, PublicKey, SecretKey, Signature};
use libc::tm;
use rand::{seq::SliceRandom, Rng, RngCore};
use criterion::{black_box,criterion_group,criterion_main,Criterion};
use rainfall::{batch, merkle::{self, MerkleTree}};


const BATCH_SIZE:usize = 1<<16;

fn generate_key_pair() -> (SecretKey,PublicKey) {
    let mut rng = rand::thread_rng();
    let mut ikm = [0u8;32];
    rng.fill_bytes(&mut ikm);
    let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
    let pk = sk.sk_to_pk();
    (sk,pk)
}

fn verify_sig(aggr_key: PublicKey,aggr_sig: Signature) {
    let k = aggr_key;
    let sig = aggr_sig;
    let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    let res = sig.verify(true, b"msgtobesigned", dst, &[], &k, true);
}

fn multiple_go_pks(list_pks: &Vec<&PublicKey>) {
    let first = list_pks[0];
    let mut start = AggregatePublicKey::from_public_key(first);
    for i in 1..BATCH_SIZE {
        let pk = list_pks[i];
        start.add_aggregate(&AggregatePublicKey::from_public_key(pk));
    }
}

fn multiple_go_sigs(list_sigs: &Vec<&Signature>) {
    let first = list_sigs[0];
    let mut start = AggregateSignature::from_signature(first);
    for i in 1..BATCH_SIZE {
        let sig = list_sigs[i];
        start.add_aggregate(&AggregateSignature::from_signature(sig));
    }
}


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


struct NodeT {
    tuple: (AggregateSignature,AggregatePublicKey),
    index: Option<usize>,
    left_child: Option<Box<NodeT>>,
    right_child: Option<Box<NodeT>>,
}

struct SignatureTree {
    root: Option<NodeT>, 
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
    fn new(list_sigs: &Vec<&Signature>,list_pks: &[&PublicKey]) -> Self {
        assert!(!list_sigs.is_empty() && list_pks.len() == list_sigs.len());

        let mut tmp: VecDeque<NodeT> = list_sigs.into_iter()
            .enumerate()
            .zip(list_pks.into_iter())
            .map(|((idx,s),p)| NodeT::new(AggregateSignature::from_signature(s),AggregatePublicKey::from_public_key(p), Some(idx), None, None))
            .collect();

        /*shuffle the array */
        // tmp.make_contiguous().shuffle(&mut rand::thread_rng());

        while tmp.len() > 1 {
            let len = tmp.len()/2;
            // println!("{}",len);
            for i in 0..len {
                let mut l1 = tmp.pop_front().unwrap();
                let l2 = tmp.pop_front().unwrap();
                l1.tuple.0.add_aggregate(&l2.tuple.0);
                l1.tuple.1.add_aggregate(&l2.tuple.1);
                tmp.push_back(NodeT::new(l1.tuple.0,l1.tuple.1,None,Some(l1),Some(l2)));
            }
        }

        Self {
            root: tmp.pop_back(),
        }
    }

    fn check(&self, message: &[u8]) -> Vec<usize> {
        
        let now: SystemTime = SystemTime::now();
        let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
        let mut stack:Vec<&NodeT> = Vec::new();
        let root = self.root.as_ref().unwrap();
        stack.push(root);
        let mut fake_index: Vec<usize> = Vec::new();
        let mut nb = 0;
        let mut iter = 0;
        
        while !stack.is_empty() {
            let curr = stack.pop().expect("failed to unwrap");
            let sig = curr.tuple.0.to_signature();
            let pk = curr.tuple.1.to_public_key();
            match sig.verify(true, message, dst, &[], &pk, true) {
                blst::BLST_ERROR::BLST_SUCCESS => {
                },
                blst::BLST_ERROR::BLST_VERIFY_FAIL => {
                    if curr.left_child.is_none() && curr.right_child.is_none() {
                        fake_index.push(curr.index.expect("the leaves of the tree have to have an index"));
                        nb+=1;
                    }else {
                        // nb +=1;
                        stack.push(curr.right_child.as_ref().unwrap());
                        stack.push(curr.left_child.as_ref().unwrap());
                    }

                },
                e => println!("{:?}", e),
            }
            iter +=1;

            // if now.elapsed().unwrap() > Duration::from_millis(550) {
            //     println!("{}",nb);
            //     println!("number of verifs made {}",iter);
            //     break;
            // }
        }
        println!("{:?}",now.elapsed().unwrap());
        fake_index
    }

}



fn binary_search(list_pks: &[&PublicKey], list_sigs: &[&Signature], message: &[u8]) -> Vec<usize>{ 
    assert!(list_sigs.len() == list_pks.len());
    let now: SystemTime = SystemTime::now();
    let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    let mut stack: Vec<(usize,usize)> = Vec::new();
    stack.push((0,list_pks.len()-1));
    /*Vec to store the indices of the unvalid signatures */
    let mut fake: Vec<usize> = Vec::new();
    while !stack.is_empty() {


        let (lowerbound, upperbound) = stack.pop().expect("can't pop");
        
        let agg_pk = aggregate_keys_fast(list_pks,lowerbound,upperbound);
        let agg_sigs = aggregate_sigs_fast(list_sigs,lowerbound,upperbound);
        
        match agg_sigs.verify(true, message, dst, &[], &agg_pk, true) {
            
            /* Case where the test is successful, this means there are no invalid signatures in this section*/
            blst::BLST_ERROR::BLST_SUCCESS => (),
            /*Case where the test is unsuccessful, we will then proceed with a binary search 
            to find the falsified signatures */
            blst::BLST_ERROR::BLST_VERIFY_FAIL => {
                if lowerbound==upperbound {
                    fake.push(lowerbound);
                }else {
                    let mid = (upperbound-lowerbound + 1) / 2;
                    stack.push((lowerbound, lowerbound+mid-1));
                    stack.push((lowerbound+mid, upperbound)); 
                }
            }
            e => println!("{:?}",e),
        }
        println!("time for aggregation {:?}",now.elapsed());
    }

    println!("{:?}",now.elapsed().unwrap());
    fake
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut input= [0u8;128];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut input);
    let leaves = VecDeque::from((0..BATCH_SIZE).map(|x| Node::new(blake3::hash(&input), None, None)).collect::<Vec<Node>>());
    
    let mut pks: Vec<PublicKey> = vec![];
    let mut sigs: Vec<Signature> = vec![];
    for i in 0..BATCH_SIZE{
        let (sk,pk) = generate_key_pair();
        let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
        let signed;
        signed = sk.sign(b"msgmsgmsg", dst, &[]);
        sigs.push(signed);
        pks.push(pk);
    }

    let sigs_borrow:Vec<&Signature> = sigs.iter().collect();
    let pks_borrow:Vec<&PublicKey> = pks.iter().collect();
    let tree = SignatureTree::new(&sigs_borrow, &pks_borrow);
    // let pks_borrow_arr: [&PublicKey;BATCH_SIZE] = pks_borrow[..].try_into().expect("failed");
    // let sigs_borrow_arr: [&Signature;BATCH_SIZE] = sigs_borrow[..].try_into().expect("failed");

    // let sigz = AggregateSignature::aggregate(&sigs_borrow_arr, true).unwrap();
    // let key = AggregatePublicKey::aggregate(&pks_borrow_arr, true).unwrap();

    // let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    // let res = sigz.to_signature().verify(true, b"msgtobesigned", dst, &[], &key.to_public_key(), true);
    // println!("{:?}",res);

    
    // c.bench_function("hash test", |b| b.iter(|| blake3::hash(black_box(b"hello"))));
    // c.bench_function("build merkle tree", |b| b.iter(|| MerkleTree::new(black_box(&leaves))));
    // c.bench_function("test split at", |b| b.iter(|| test_split(&pks_borrow[..])));
    // c.bench_function("verify bls sig", |b| b.iter(|| verify_sig(key.to_public_key(), sigz.to_signature())));
    // c.bench_function("agg public key in one go", |b| b.iter(|| AggregatePublicKey::aggregate(&pks_borrow[..], true)));
    // c.bench_function("agg public key in multiple steps", |b| b.iter(|| multiple_go_pks(&pks_borrow)));
    // c.bench_function("agg sigs", |b| b.iter(|| AggregateSignature::aggregate(&sigs_borrow[..], true)));
    // c.bench_function("agg sigs multiple iter", |b| b.iter(|| multiple_go_sigs(&sigs_borrow)));
    // c.bench_function("binary search to find which signatures are wrong", |b| b.iter(|| binary_search(&pks_borrow[..], &sigs_borrow[..], b"msgtobesigned")));
    // c.bench_function("test of aggregate keys fast", |b| b.iter(|| aggregate_keys_fast(&pks_borrow[..], 0, BATCH_SIZE-1  )));
    // c.bench_function("test of aggregate keys fast", |b| b.iter(|| aggregate_sigs_fast(&sigs_borrow[..], 0, BATCH_SIZE-1  )));
    // c.bench_function("build only signature tree", |b| b.iter(|| SignatureTree::new(black_box(&sigs_borrow), black_box(&pks_borrow))));
    c.bench_function("benchmark to build signature tree + find false signature", |b| b.iter(||{
        tree.check( black_box(b"msgtobesigned"));
    }));
}
criterion_group!{
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = criterion_benchmark
}

// (benches,criterion_benchmark);
criterion_main!(benches);
