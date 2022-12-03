use crate::Payload;
use async_std::prelude::Stream;
use fnv::FnvHashSet;
use futures::{FutureExt, StreamExt};
use log::{debug, error};
use sc_network::{Multiaddr, PeerId, ReputationChange};
use sc_network_common::config::{MultiaddrWithPeerId, NonDefaultSetConfig};
use sc_network_common::protocol::event::Event;
use sc_network_common::protocol::ProtocolName;
use sc_network_common::service::{
    NetworkBlock, NetworkEventStream, NetworkNotification, NetworkPeers, NotificationSender,
    NotificationSenderError,
};
use sc_network_gossip::{
    GossipEngine, MessageIntent, Network as GossipNetwork, Network, ValidationResult, Validator,
    ValidatorContext,
};
use sp_runtime::traits::{Block, Hash, Header, NumberFor};
use std::collections::HashSet;
use std::marker::PhantomData;
use std::pin::Pin;
use std::{
    collections::BTreeMap,
    // after rust 1.63 theese are better on linux than parking_lot ones
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};
use tokio::time::Instant;

const GOSSIP_NAME: &str = "/pdex/1";

pub type MessageHash = [u8; 8];

/// Gets the name of our gossip protocol
/// intended to be used with `gossip_peers_set_config`
pub fn gossip_protocol_name() -> ProtocolName {
    GOSSIP_NAME.into()
}

/// Configuration geterating method for number of peers per our protocol and per-peer set
/// of non-reserved nodes
pub fn gossip_peers_set_config(protocol_name: ProtocolName) -> NonDefaultSetConfig {
    // max peers
    let mut cfg = NonDefaultSetConfig::new(protocol_name, 1024 * 1024);
    // per node peers
    cfg.allow_non_reserved(25, 25);
    cfg
}

/// Gossip engine messages topic
// hash = b"pdex"; for example (32 bits)
pub fn topic<B: Block>(hash: [u8; 4]) -> B::Hash {
    <<B::Header as Header>::Hashing as Hash>::hash(&hash)
}

/// Holds our currently processed messages from other peers per block
pub struct KnownSigned<B: Block> {
    // which block we've finished last
    last_done: Option<NumberFor<B>>,
    // which blocks we're still processing (not finalized yet)
    live: BTreeMap<NumberFor<B>, FnvHashSet<MessageHash>>,
}

/// Implements sc_network_gossip::Validator
/// used for instatiation and gossip processing
pub struct GossipValidator<B: Block> {
    topic: B::Hash,
    known_signed: RwLock<KnownSigned<B>>,
    next_rebroadcast: Mutex<Instant>,
}

/// Our actual node working with messages
pub struct GossipNode<B: Block> {
    gossip_engine: Arc<Mutex<GossipEngine<B>>>,
    gossip_validator: Arc<GossipValidator<B>>,
}

impl<B> GossipNode<B>
where
    B: Block,
{
    pub async fn run(&mut self) {
        let mut gossips = Box::pin(
            self.gossip_engine
                .lock()
                .unwrap()
                .messages_for(topic::<B>(*b"pdex"))
                .filter_map(|notification| async move {
                    debug!(
                    target: "POC",
                    "Got new gossip message for pdex"
                    );
                    serde_json::from_slice::<Payload>(&notification.message[..]).ok()
                }),
        );
        loop {
            let engine = self.gossip_engine.clone();
            let gossip_engine_unpin =
                futures::future::poll_fn(|cx| engine.lock().unwrap().poll_unpin(cx));
            futures::select! {
                gossip = gossips.next().fuse() => {
                    if let Some(gossip) = gossip {
                        self.on_gossip(gossip);
                    } else {
                        debug!(
                            target: "POC",
                            "No new gossip in parsed message :S"
                        );
                        continue;
                    }
                }
                _ = gossip_engine_unpin.fuse() => {
                    error!(
                        target: "POC",
                        "Gossip engine has terminated!"
                    );
                    return;
                }
            }
        }
    }

    pub fn on_gossip(&mut self, gossip: Payload) {
        //TODO: process gossip here
        // can implement any checks we want here
        // and send gossip like this:
        let new_payload = serde_json::to_vec(&gossip).unwrap();
        self.gossip_engine
            .lock()
            .unwrap()
            .gossip_message(topic::<B>(*b"pdex"), new_payload, false);
        debug!(
            target: "POC",
            "Send new payload"
        );
    }
}

impl<B: Block> KnownSigned<B> {
    pub fn new() -> Self {
        Self {
            last_done: None,
            live: BTreeMap::new(),
        }
    }
}

impl<B> GossipValidator<B>
where
    B: Block,
{
    pub fn new(topic_bytes: [u8; 4]) -> Self {
        GossipValidator {
            topic: topic::<B>(topic_bytes),
            known_signed: RwLock::new(KnownSigned::new()),
            next_rebroadcast: Mutex::new(Instant::now() + Duration::from_secs(60)),
        }
    }
}

impl<B> Validator<B> for GossipValidator<B>
where
    B: Block,
{
    fn validate(
        &self,
        _context: &mut dyn ValidatorContext<B>,
        sender: &PeerId,
        mut data: &[u8],
    ) -> ValidationResult<B::Hash> {
        //TODO: Should be more thorrow with validation :)
        if let Ok(msg) = serde_json::from_slice::<Payload>(data) {
            ValidationResult::ProcessAndKeep(self.topic)
        } else {
            ValidationResult::Discard
        }
    }

    fn message_expired<'a>(&'a self) -> Box<dyn FnMut(B::Hash, &[u8]) -> bool + 'a> {
        //TODO: do actual check
        Box::new(move |_topic, _data| false) //all are ok now
    }

    fn message_allowed<'a>(
        &'a self,
    ) -> Box<dyn FnMut(&PeerId, MessageIntent, &B::Hash, &[u8]) -> bool + 'a> {
        //TODO: do actual check
        Box::new(move |_who, _intent, _topic, _data| true) //all are ok now
    }
}

pub async fn start_gossip_validator<B: Block, N>(gossip_network: N)
where
    N: GossipNetwork<B> + Clone + Send + Sync + 'static,
{
    let gossip_validator = Arc::new(GossipValidator::<B>::new(*b"pdex"));
    let gossip_engine = Arc::new(Mutex::new(GossipEngine::new(
        gossip_network,
        gossip_protocol_name(),
        gossip_validator.clone(),
        None,
    )));
    let mut node = GossipNode {
        gossip_engine,
        gossip_validator,
    };
    node.run().await
}

#[derive(Clone)]
pub struct OurNetwork<B: Block> {
    pub _block: PhantomData<B>,
}

impl<B: Block> NetworkPeers for OurNetwork<B> {
    fn set_authorized_peers(&self, peers: HashSet<PeerId>) {
        todo!()
    }

    fn set_authorized_only(&self, reserved_only: bool) {
        todo!()
    }

    fn add_known_address(&self, peer_id: PeerId, addr: Multiaddr) {
        todo!()
    }

    fn report_peer(&self, who: PeerId, cost_benefit: ReputationChange) {
        todo!()
    }

    fn disconnect_peer(&self, who: PeerId, protocol: ProtocolName) {
        todo!()
    }

    fn accept_unreserved_peers(&self) {
        todo!()
    }

    fn deny_unreserved_peers(&self) {
        todo!()
    }

    fn add_reserved_peer(&self, peer: MultiaddrWithPeerId) -> Result<(), String> {
        todo!()
    }

    fn remove_reserved_peer(&self, peer_id: PeerId) {
        todo!()
    }

    fn set_reserved_peers(
        &self,
        protocol: ProtocolName,
        peers: HashSet<Multiaddr>,
    ) -> Result<(), String> {
        todo!()
    }

    fn add_peers_to_reserved_set(
        &self,
        protocol: ProtocolName,
        peers: HashSet<Multiaddr>,
    ) -> Result<(), String> {
        todo!()
    }

    fn remove_peers_from_reserved_set(&self, protocol: ProtocolName, peers: Vec<PeerId>) {
        todo!()
    }

    fn add_to_peers_set(
        &self,
        protocol: ProtocolName,
        peers: HashSet<Multiaddr>,
    ) -> Result<(), String> {
        todo!()
    }

    fn remove_from_peers_set(&self, protocol: ProtocolName, peers: Vec<PeerId>) {
        todo!()
    }

    fn sync_num_connected(&self) -> usize {
        todo!()
    }
}

impl<B: Block> NetworkEventStream for OurNetwork<B> {
    fn event_stream(&self, name: &'static str) -> Pin<Box<dyn Stream<Item = Event> + Send>> {
        todo!()
    }
}

impl<B: Block> NetworkNotification for OurNetwork<B> {
    fn write_notification(&self, target: PeerId, protocol: ProtocolName, message: Vec<u8>) {
        todo!()
    }

    fn notification_sender(
        &self,
        target: PeerId,
        protocol: ProtocolName,
    ) -> Result<Box<dyn NotificationSender>, NotificationSenderError> {
        todo!()
    }
}

impl<B: Block> NetworkBlock<<B::Header as Header>::Hashing, NumberFor<B>> for OurNetwork<B> {
    fn announce_block(&self, hash: <B::Header as Header>::Hashing, data: Option<Vec<u8>>) {
        todo!()
    }

    fn new_best_block_imported(&self, hash: <B::Header as Header>::Hashing, number: NumberFor<B>) {
        todo!()
    }
}
