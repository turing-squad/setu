// Copyright 2018 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

//! A basic chat application with logs demonstrating libp2p and the gossipsub protocol
//! combined with mDNS for the discovery of peers to gossip with.
//!
//! Using two terminal windows, start two instances, typing the following in each:
//!
//! ```sh
//! cargo run --example gossipsub-chat --features=full
//! ```
//!
//! Mutual mDNS discovery may take a few seconds. When each peer does discover the other
//! it will print a message like:
//!
//! ```sh
//! mDNS discovered a new peer: {peerId}
//! ```
//!
//! Type a message and hit return: the message is sent and printed in the other terminal.
//! Close with Ctrl-c.
//!
//! You can open more terminal windows and add more peers using the same line above.
//!
//! Once an additional peer is mDNS discovered it can participate in the conversation
//! and all peers will receive messages sent from it.
//!
//! If a participant exits (Control-C or otherwise) the other peers will receive an mDNS expired
//! event and remove the expired peer from the list of known peers.

use async_std::io;
use blst::blst_keygen;
use blst::blst_scalar;
use blst::min_sig::*;
use futures::future;
use futures::{prelude::*, select};
use libp2p::{identity, NetworkBehaviour, PeerId};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::error::Error;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;
use std::time::Duration;
use structopt::StructOpt;
use hex_literal::hex;
use std::time;
use web3::{
    contract::{Contract, Options},
    futures::{StreamExt},
    types::FilterBuilder,
};
use core::str::FromStr;

use tokio::sync::mpsc::{channel, Receiver, Sender};

#[derive(Debug, StructOpt)]
pub struct Cli {
    #[structopt(long = "public-key", default_value = "0")]
    pub public_key: u8,
}

pub async fn create_public_key_map() -> HashMap<u32, PublicKey> {
    let mut public_key_map: HashMap<u32, PublicKey> = HashMap::new();
    for x in 0..10 {
        let mut ikm = [x as u8; 32];
        let sk_1 = SecretKey::key_gen(&ikm, &[]).unwrap();
        let pk_1 = sk_1.sk_to_pk();
        public_key_map.insert(x, pk_1);
    }
    public_key_map
}

// TODO: We need to create this for bootnode and peer discovery
pub async fn create_peer_id_map() -> HashMap<u32, PublicKey> {
    let mut peer_id_map: HashMap<u32, PublicKey> = HashMap::new();
    peer_id_map
}

// We create a custom network behaviour that combines Gossipsub and Mdns.
#[derive(NetworkBehaviour)]
struct MyBehaviour {
    gossipsub: Gossipsub,
    mdns: Mdns,
}
// To content-address message, we can take the hash of message and use it as an ID.
fn message_id_fn(message: &GossipsubMessage) -> MessageId {
    let mut s = DefaultHasher::new();
    message.data.hash(&mut s);
    MessageId::from(s.finish().to_string())
}

// We create a struct for interacting with Ethereum
pub struct EthereumListener {
    pub secret_key: [u8; 32],
}

impl EthereumListener{
    pub fn new() -> Self {
        EthereumListener{
            secret_key: [0; 32]
        }
    }

    pub async fn run(&self, g_sender: Sender<(&'static str, Vec<u8>)>, secret_key: Arc<SecretKey>, auth_index: u32){
        // Initialize Transport
        let web3 = web3::Web3::new(web3::transports::WebSocket::new("ws://localhost:8545").await.unwrap());
        log::info!(target:"Ethereum", "Initialized Ethereum Transport successfully");

        // Fetch bytecode from the contract
        let bytecode = include_str!("../SimpleEvent.bin");

        // Ethereum accounts
        let accounts = web3.eth().accounts().await.unwrap();
        log::info!(target: "Ethereum","accounts: {:?}", &accounts);

        // Initialize Contract from Address
        let contract = Contract::from_json(web3.eth(), ethereum_types::H160::from_str("0x4d470146215d085c75767b717dbb8d3b4468f893").unwrap(), include_bytes!("../SimpleEvent.abi")).unwrap();
        log::info!(target: "Ethereum", "Initialized Contract from ABI and Address successfully");

        // Filter for Hello event in our contract
        let filter = FilterBuilder::default()
            .address(vec![contract.address()])
            .topics(
                Some(vec![hex!(
                "d282f389399565f3671145f5916e51652b60eee8e5c759293a2f5771b8ddfd2e"
            )
                    .into()]),
                None,
                None,
                None,
            )
            .build();

        let mut sub = web3.eth_subscribe().subscribe_logs(filter).await.unwrap();
        let clone_g_sender = g_sender.clone();

        while let Some(log) = sub.next().await {
            let decoded_event = contract.abi().event("Hello").unwrap().parse_log(ethabi::RawLog{ topics: log.clone().unwrap().topics, data: log.clone().unwrap().data.0 }).unwrap();
            log::info!(target: "Ethereum", "Received Event: ({:#?}: 0x{})", decoded_event.params[0].name, decoded_event.params[0].value);

            let address = format!("0x{}", decoded_event.params[0].value);
            let mut payload = Payload::create_payload_sync(secret_key.clone(), address.as_bytes(), auth_index as u8);
            payload.authority_index[auth_index as usize] = 1;
            let payload_bytes = serde_json::to_vec(&payload).unwrap();
            clone_g_sender
                .send(("thea", payload_bytes))
                .await
                .expect("Failed to send new payload to pipe");
        }
    }
}

pub struct SubstrateRunner{
    pub secret_key: [u8; 32]
}

impl SubstrateRunner{
    pub fn new() -> Self {
        SubstrateRunner{
            secret_key: [0; 32]
        }
    }

    pub async fn run(&self, mut receiver: Receiver<(Vec<u8>)>) {
        while let Some((bytes)) = receiver.recv().await {
            #[cfg(aggregator)]
            log::info!(target:"Substrate", "Received Majority event forwarding to Substrate from the following: {}", String::from_utf8(bytes).unwrap());
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("Starting gossip based node");
    let NetworkWorkerParams {
        topics,
        seed_nodes,
        boot_nodes,
        port,
        auth,
    } = NetworkWorkerParams::from_args();
    env_logger::init();
    let (g_sender, g_receive) = channel(100);
    let (s_sender, s_receive) = channel(100);
    let g_sender_eth = g_sender.clone();
    let auth_index = Arc::new(auth);
    let mut ikm = [auth as u8; 32];
    let sk_1 = SecretKey::key_gen(&ikm, &[]).unwrap();
    let pk_1 = sk_1.sk_to_pk();
    let sk = Arc::new(sk_1.clone());
    log::info!(target:"GossipNode", "Local Public Key: {:?}", pk_1.serialize());
    // println!("Local Public Key: {:?}", pk_1.serialize());
    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());
    let identity = (local_peer_id, local_key);
    log::info!(target: "GossipNode", "Building network");
    let mut thea_net = TheaNetwork::new(
        identity.0,
        port,
        identity.1,
        Arc::new(sk_1),
        *auth_index,
        g_sender,
        g_receive,
    )
    .await;
    log::info!(target: "GossipNode", "Starting network");

    // Ethereum Sub Module
    let ethereum_listener = EthereumListener::new();

    // Substrate sub module
    let substrate = SubstrateRunner::new();


    let block_import_handler = tokio::spawn(async move {
        ethereum_listener.run(g_sender_eth, sk.clone(), auth).await
    });

    let block_fetcher_handler = tokio::spawn(async move {
        thea_net.run(topics, seed_nodes, boot_nodes, None, s_sender).await
    });

    let substrate_runner = tokio::spawn(async move {
        substrate.run(s_receive).await
    });

    if let Err(err) = tokio::try_join!(block_import_handler, block_fetcher_handler, substrate_runner) {
        return Err(anyhow::Error::new(err));
    }
    Ok(())
}

use async_std::prelude::FutureExt;
use libp2p::gossipsub::{Gossipsub, GossipsubMessage, MessageId};
use libp2p::mdns::Mdns;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub struct SignatureWrapper([u8; 96]);

#[derive(Serialize, Deserialize, Clone)]
struct Payload {
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
            authority_index: vec![0_u8; 10],
        };
        payload
    }
    pub fn create_payload_sync(sk: Arc<SecretKey>, msg: &[u8], auth_index: u8) -> Payload {
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
            authority_index: vec![0_u8; 10],
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

pub async fn create_aggregate_public_key_from_indexes(
    authority_indexes: Vec<u8>,
    public_key_map: HashMap<u32, PublicKey>,
) -> AggregatePublicKey {
    let mut agg_pk: Option<AggregatePublicKey> = None;
    for x in 0..10 {
        if authority_indexes[x as usize] == 1 {
            // Fetch Public Key
            let pk = public_key_map[&(x as u32)];
            if agg_pk.is_none() {
                agg_pk = match AggregatePublicKey::aggregate(&[&pk], false) {
                    Ok(agg_sig) => Some(agg_sig),
                    Err(err) => panic!("Unable to create Aggregate Public KEy"),
                };
            } else {
                let mut new_agg_pk = agg_pk.unwrap();
                new_agg_pk.add_public_key(&pk, false).unwrap();
                agg_pk = Some(new_agg_pk);
            }
        }
    }
    agg_pk.unwrap()
}
// For Testing Purposes, We will check for 100%
pub fn check_for_threshold(authority_index: Vec<u8>) -> bool {
    let mut flag = false;
    let mut counter = 0;
    for x in authority_index {
        if x == 1 {
            counter += 1;
        }
    }
    if counter > 5 {
        flag = true;
    }
    flag
}

use libp2p_poc::network_worker::{TheaEventHandler, TheaNetwork};
use libp2p_poc::sc_network::{start_gossip_validator, OurNetwork};
use libp2p_poc::NetworkWorkerParams;
use serde_json::Value;

#[test]
fn test_payload_serialization_and_deserialization() {
    let mut ikm = [1u8; 32];
    let sk_1 = SecretKey::key_gen(&ikm, &[]).unwrap();
    let pk_1 = sk_1.sk_to_pk();
    let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    let msg = b"Faisal";
    let sig = sk_1.sign(msg, dst, &[]);
    let sig_bytes: [u8; 96] = sig.serialize();
    let sig_part_1: &[u8] = &sig_bytes[0..32];
    let sig_part_2: &[u8] = &sig_bytes[32..64];
    let sig_part_3: &[u8] = &sig_bytes[64..96];
    let payload = Payload {
        signature_part_1: sig_part_1.to_vec(),
        signature_part_2: sig_part_2.to_vec(),
        signature_part_3: sig_part_3.to_vec(),
        msg: msg.to_vec(),
        authority_index: vec![0, 0, 0],
    };
    // Let's serialize
    let serialized_payload: Vec<u8> = serde_json::to_vec(&payload).unwrap();

    let deserialized_payload: Payload = serde_json::from_slice(&serialized_payload).unwrap();
    assert_eq!(
        deserialized_payload.signature_part_1,
        payload.signature_part_1
    );
    // let deserialized_payload: Payload = serde_json::from_str(&serialized_payload).unwrap();

    // Reconstruct the signature
    let mut recon_signature = deserialized_payload.signature_part_1;
    recon_signature.extend(deserialized_payload.signature_part_2);
    recon_signature.extend(deserialized_payload.signature_part_3);
    assert_eq!(recon_signature, sig_bytes.to_vec());

    let recon_sig = Signature::from_bytes(&recon_signature).unwrap();
    let err = recon_sig.verify(true, msg, dst, &[], &pk_1, true);
    // panic!("{:#?}", err);
    assert_eq!(1, 1);
}
