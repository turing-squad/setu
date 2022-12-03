pub mod network_worker;

use blst::min_sig::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use structopt::StructOpt;
#[derive(Debug, StructOpt)]
pub struct NetworkWorkerParams {
    #[structopt(long = "topics", short = "t", default_value = "thea")]
    pub topics: Vec<String>,
    #[structopt(long = "seed-nodes", short = "s", default_value = "")]
    pub seed_nodes: Vec<String>,
    #[structopt(long = "boot-nodes", short = "b", default_value = "")]
    pub boot_nodes: Vec<String>,
    #[structopt(long = "port", short = "p", default_value = "26000")]
    pub port: u16,
    #[structopt(long = "auth", short = "i", default_value = "0")]
    pub auth: u32,
    #[structopt(long = "agg", short = "a")]
    pub aggregator: bool
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Payload {
    signature_part_1: Vec<u8>,
    signature_part_2: Vec<u8>,
    signature_part_3: Vec<u8>,
    msg: Vec<u8>,
    authority_index: Vec<u8>,
}

impl Payload {
    pub async fn create_payload(sk: Arc<SecretKey>, msg: &[u8], auth_index: u8) -> Payload {
        let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
        let sig = sk.sign(msg, dst, &[]);
        let agg_sig = match AggregateSignature::aggregate(&[&sig], true) {
            Ok(agg) => agg.to_signature(),
            Err(err) => panic!("aggregate failure: {:?}", err),
        };
        let sig_bytes: [u8; 96] = agg_sig.serialize();
        let sig_part_1: &[u8] = &sig_bytes[0..32];
        let sig_part_2: &[u8] = &sig_bytes[32..64];
        let sig_part_3: &[u8] = &sig_bytes[64..96];
        let payload = Payload {
            signature_part_1: sig_part_1.to_vec(),
            signature_part_2: sig_part_2.to_vec(),
            signature_part_3: sig_part_3.to_vec(),
            msg: msg.to_vec(),
            authority_index: vec![0_u8; 1000],
        };
        payload
    }
    pub async fn create_new_payload(
        sk: Arc<SecretKey>,
        auth_index: u8,
        old_payload: &Payload,
        mut agg_sig: AggregateSignature,
    ) -> Payload {
        let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
        let sig = sk.sign(&old_payload.msg, dst, &[]);
        agg_sig.add_signature(&sig, false).unwrap();
        let sig_bytes: [u8; 96] = agg_sig.to_signature().serialize();
        let sig_part_1: &[u8] = &sig_bytes[0..32];
        let sig_part_2: &[u8] = &sig_bytes[32..64];
        let sig_part_3: &[u8] = &sig_bytes[64..96];
        let mut new_authority_index = old_payload.authority_index.clone();
        new_authority_index[auth_index as usize] = 1;
        let payload = Payload {
            signature_part_1: sig_part_1.to_vec(),
            signature_part_2: sig_part_2.to_vec(),
            signature_part_3: sig_part_3.to_vec(),
            msg: old_payload.msg.clone(),
            authority_index: new_authority_index,
        };
        payload
    }
}
