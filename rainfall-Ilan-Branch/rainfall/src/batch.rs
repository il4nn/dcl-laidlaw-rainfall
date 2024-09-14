use std::{fmt, mem, vec};
use crate::merkle::MerkleTree;
use crate::signature_tree::SignatureTree;
use blst::{min_pk::{AggregateSignature, PublicKey, Signature}, BLST_ERROR};
use serde::{Serialize,Deserialize};
use libc::*;
use std::time::{SystemTime,Duration};

type SequenceNumber = u64;
type NumericalIdentifier = u64;
type BatchId = usize;
type PositionInBatch = usize;

const BATCH_SIZE:u64 = 1<<16 ;
const TIMEOUT_DURATION_BATCH: u64= 500;
const FAKE_ROOT: [u8;32] = [200, 117, 111, 57, 59, 197, 34, 95, 163, 98, 125, 151, 19, 45, 52, 158, 129, 137, 
                            95, 68, 115, 72, 118, 235, 175, 93, 230, 204, 31, 175, 122, 223];


#[derive(Serialize,Deserialize,Clone,Debug,PartialEq, Eq,Hash)]
pub struct Payload {
    pub num_id : NumericalIdentifier,
    pub seq_num: SequenceNumber,
    pub message: Vec<u8>,
}

#[derive(Debug)]
pub struct NotAPayload;
impl fmt::Display for NotAPayload    {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Expected a bit (0 or 1) but got something else")
    }
}

#[derive(Debug)]
pub struct BatchConstruction { 
    batch_id: BatchId,
    addrs: Vec<sockaddr_in>,
    clients_ids : Vec<u64>,
    payloads : Vec<Payload>,
    size: usize,
}

#[derive(Debug)]
pub struct BatchProposal {
    batch_id : BatchId,
    pub merkle: MerkleTree,
    pub bitmap: Vec<bool>,
    list_sigs: Vec<Signature>,
    lists_pks: Vec<PublicKey>,
    pos_to_cliendid: Vec<usize>,
    start_time: Option<SystemTime>,
    timeout_duration: Duration,
    has_timeout: bool,
}

#[derive(Debug)]
pub struct DistilledBatch {
    batch_id : BatchId,
    pub sigtree: SignatureTree,
}

#[derive(Debug)]

pub enum BatchType {
    Construction(BatchConstruction),
    Proposal(BatchProposal),
    DistilledBatch(DistilledBatch),
}

#[derive(Debug)]
pub struct BatchManager {
    pub batches: Vec<BatchType>,
    batch_id: BatchId,
}

impl BatchConstruction {
    pub fn new(batch_id: BatchId) -> Self{
        Self {
            batch_id,
            addrs: Vec::new(),
            clients_ids: Vec::new(),
            payloads: Vec::new(),
            size: 0,
        }
    }


    pub fn to_proposal(self) -> BatchProposal {
        BatchProposal::new(self.payloads, self.batch_id)
    }

    pub fn add(&mut self, addr: sockaddr_in, client_id: u64, payload: Payload) -> PositionInBatch{ 
        assert!(self.addrs.len() == self.clients_ids.len() && self.payloads.len() == self.clients_ids.len());
        assert!(self.addrs.len() == self.size as usize);

        self.addrs.push(addr);
        self.clients_ids.push(client_id);
        self.payloads.push(payload);
        self.size += 1;

        let pos = (self.size - 1) as usize;
        return pos
    }

    pub fn get_size(&self) -> usize {
        self.size
    }

    pub fn get_batch_id(&self) -> BatchId {
        self.batch_id
    }
}


impl BatchManager {
    pub fn new() -> Self {
        Self {
            batches: Vec::new(),
            batch_id: 0
        }
    }

    pub fn add_batch(&mut self) {
        if !self.batches.is_empty() {
            self.increment_batch_id();
        }
        
        let wip = BatchConstruction::new(self.batch_id);
        self.batches.push(BatchType::Construction(wip));
    }

    pub fn add_to_construction(&mut self,addr: sockaddr_in, client_id: u64, payload: Payload) -> (BatchId, PositionInBatch, Option<(Vec<sockaddr_in>,MerkleTree,Vec<u64>)>){ 
        
        /*First we check if the current batch in construction is full.
        If it is the case, we create a new batch in construction and return 
        the batch proposal to the server so that it can the proofs of inclusions
        to the clients 
         */
        let mut idx_wip = self.batch_id;
        let mut tuple: Option<(Vec<sockaddr_in>,MerkleTree,Vec<u64>)> = None;
        let mut has_created = false;
        let batch = &self.batches[idx_wip as usize];
        

        match batch {
            BatchType::Construction(wip) => {
                if wip.get_size() >= BATCH_SIZE as usize{
                    let (batch_id, vec_addrs,merkle,client_ids) = self.construction_to_proposal(idx_wip);
                    tuple = Some((vec_addrs,merkle,client_ids));
                    idx_wip = batch_id;
                    has_created = true;
                }
            },
            _ => todo!(),
        }

        if has_created {
            self.add_batch();
        }

        let batch_to_add = &mut self.batches[idx_wip as usize];
        let mut pos = 0;
        if let BatchType::Construction(wip) = batch_to_add {
            pos = wip.add(addr, client_id, payload);
        }

        (idx_wip,pos,tuple)
    }


    // pub fn add_to_proposal(&mut self, batch_id:usize, pos:usize,pk: PublicKey, sig: Signature) {

    pub fn add_to_proposal(&mut self, batch_id:usize, pos:usize, client_id: usize, sig: Signature, pk: PublicKey, c: &mut i32) {
        assert!(batch_id <= self.batches.len());
        
        let batch = &mut self.batches[batch_id];
        match batch {
            BatchType::Proposal(proposal) => {
                match proposal.start_time {
                    Some(start) => {
                        if start.elapsed().unwrap() > proposal.timeout_duration {
                            if !proposal.has_timeout {
                                println!("finished batch, timeout expired: {}",c);
                                proposal.has_timeout = true;
                            }
                            self.proposal_to_distilled(batch_id);
                            return;
                        }
                    },
                    None => {}
                } 
                *c+=1;
                proposal.list_sigs.push(sig);
                proposal.lists_pks.push(pk);
                proposal.bitmap[pos] = true;
                proposal.pos_to_cliendid.push(client_id);

            },
            _ => (),
        }
    }

    pub fn add_start_time(&mut self, batch_id: BatchId) {
        assert!(batch_id < self.batches.len());

        let batch = &mut self.batches[batch_id];
        if let BatchType::Proposal(proposal) = batch {
            assert!(proposal.start_time.is_none());
            let now = SystemTime::now();
            println!("Start time: {:?}",now);
            proposal.start_time = Some(now);
        }
    }

    pub fn construction_to_proposal(&mut self,batch_id: usize) -> (BatchId,Vec<sockaddr_in>,MerkleTree,Vec<u64>){
        if let Some(batch) = self.batches.get_mut(batch_id as usize) {
            match mem::replace(batch, BatchType::Proposal(BatchProposal::new(vec![], 0))) {
                BatchType::Construction(wip) => {
                    let addrs = wip.addrs.clone();
                    let client_ids = wip.clients_ids.clone();
                    let batch_id = wip.batch_id + 1;
                    let proposal: BatchProposal = wip.to_proposal();
                    let merkle = proposal.merkle.clone();
                    *batch = BatchType::Proposal(proposal); 
                    return (batch_id,addrs,merkle,client_ids)
                },
                _ => todo!(),
            }
        }else {
            (0,vec![],MerkleTree::new(&vec![]),vec![])
        }
    }
 

    pub fn proposal_to_distilled(&mut self, batch_id: usize) {
        assert!(batch_id < self.batch_id);

        if let Some(batch) = self.batches.get_mut(batch_id as usize) {
            match mem::replace(batch, BatchType::DistilledBatch(DistilledBatch::new(vec![], vec![],0))){
                BatchType::Proposal(proposal) => {
                    let distilled = proposal.to_distilled();
                    *batch = BatchType::DistilledBatch(distilled);
                },
                _ => todo!(),
            }
        }
    }

    fn increment_batch_id(&mut self) {
        self.batch_id += 1;
    }
}


impl Payload {
    pub fn new(num_id: NumericalIdentifier,seq_num: SequenceNumber, message: Vec<u8>) -> Self{
        Self{
            num_id,
            seq_num,
            message,
        }
    }


    pub fn to_bytes(&self) -> Vec<u8>{
        let buf_len = 24 + self.message.len();
        let mut buf = vec![0;buf_len];
        // assert!(buf.len() >= buf_len);

        let serialized_id = self.num_id.to_be_bytes();
        let serialized_seq_num = self.seq_num.to_be_bytes();
        let serialized_msg_len = self.message.len().to_be_bytes();
        buf[..8].copy_from_slice(&serialized_id);
        buf[8..16].copy_from_slice(&serialized_seq_num);
        buf[16..24].copy_from_slice(&serialized_msg_len);
        buf[24..].copy_from_slice(&self.message);
        buf
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self,NotAPayload> {
        if (buf.len() < 24 || buf.len() > 1024){
            println!("size: {}",buf.len());
            return Err(NotAPayload)
        }

        let num_id = u64::from_be_bytes(buf[..8].try_into().expect("slice incorrect size"));
        let seq_num = u64::from_be_bytes(buf[8..16].try_into().expect("slice incorrect size"));
        let msg_len: usize = usize::from_be_bytes(buf[16..24].try_into().expect("slice incorrect size"));
        let mut message = vec![0;msg_len];
        message.copy_from_slice(&buf[24..(24+msg_len)]);


        Ok(Self {
            num_id,
            seq_num,
            message,
        })
    }

}


impl BatchProposal{

    pub fn new(payloads: Vec<Payload>,batch_id:BatchId) -> Self {
        // assert!(!payloads.is_empty());


        let leaves: Vec<Vec<u8>> = payloads
        .iter()
        .map(|x| x.to_bytes())
        .collect();
    
        let leaves_slice: Vec<&[u8]> = leaves.iter().map(|x| &x[..]).collect();
        let bitmap = vec![false;leaves.len()];
        
        let merkletree = MerkleTree::new(&leaves_slice);  

        Self { 
            batch_id,
            merkle: merkletree,
            bitmap,
            list_sigs: vec![],
            lists_pks: vec![],
            pos_to_cliendid: vec![],
            start_time: None,
            timeout_duration: Duration::from_millis(TIMEOUT_DURATION_BATCH),
            has_timeout: false
        }
    }

    fn to_distilled(self) ->  DistilledBatch {
        println!("transformed proposal to distilled batch");

        DistilledBatch::new(self.list_sigs,self.lists_pks, self.batch_id)
    }
}


impl DistilledBatch { 
        pub fn new(list_sigs:Vec<Signature>, list_pks: Vec<PublicKey>, batch_id: BatchId) -> Self{
    
            Self{
                batch_id,
                sigtree: SignatureTree::new(list_sigs, list_pks)
            }
        }
    }