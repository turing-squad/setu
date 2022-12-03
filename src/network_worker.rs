use crate::Payload;
use anyhow::{anyhow, Error};
use async_trait::async_trait;
use blst::min_sig::*;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use libp2p::gossipsub::{Sha256Topic, Topic};
use libp2p::identity::Keypair;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{SwarmBuilder, SwarmEvent};
use libp2p::{
    core::{
        connection::ConnectionId,
        identity,
        muxing::StreamMuxerBox,
        transport::{upgrade::Version, Boxed},
        upgrade::SelectUpgrade,
        PeerId,
    },
    dns::TokioDnsConfig,
    gossipsub::{
        self, Gossipsub, GossipsubEvent, GossipsubMessage, MessageAuthenticity, MessageId,
    },
    identify,
    kad::{store::MemoryStore, Kademlia, KademliaConfig, KademliaEvent, KademliaStoreInserts},
    mplex::MplexConfig,
    noise::{self, NoiseConfig},
    ping,
    swarm::{
        ConnectionHandler, IntoConnectionHandler, NetworkBehaviour, NetworkBehaviourAction,
        PollParameters, Swarm,
    },
    Multiaddr, NetworkBehaviour, Transport,
};
use rand::random;
use std::borrow::Cow;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, Ordering};
use std::{future::Future, time::Duration};
use std::{
    pin::Pin,
    sync::{atomic::AtomicUsize, Arc, Mutex},
    task::{Context, Poll},
};
use tokio::sync::mpsc::{channel, Receiver, Sender};

const PROTOCOL_NAME: &'static str = "/pdex/kad/0.0.0";

pub fn gossip_protocol_name() -> Vec<Cow<'static, [u8]>> {
    vec![PROTOCOL_NAME.as_bytes().into()]
}

pub struct Networker {
    /// Addresses of our node reachable by other swarm nodes
    pub local_addresses: Arc<Mutex<Vec<Multiaddr>>>,
    /// Counter of connected peers
    pub peers_count: Arc<AtomicUsize>,
    /// libp2p Swarm network
    networking: Swarm<TheaNetBehaviour>,
}

///Enum to map seperate events for different behaviours
pub enum ComposedEvent {
    Gossipsub(GossipsubEvent),
    Kademlia(KademliaEvent),
    Identify(identify::Event),
    PingEvent(ping::Event),
}

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "ComposedEvent")]
pub struct TheaNetBehaviour {
    pub gossip_sub: Gossipsub,
    pub kademlia: Kademlia<MemoryStore>,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
}

impl From<GossipsubEvent> for ComposedEvent {
    fn from(event: GossipsubEvent) -> Self {
        ComposedEvent::Gossipsub(event)
    }
}

impl From<KademliaEvent> for ComposedEvent {
    fn from(event: KademliaEvent) -> Self {
        ComposedEvent::Kademlia(event)
    }
}

impl From<ping::Event> for ComposedEvent {
    fn from(event: ping::Event) -> Self {
        ComposedEvent::PingEvent(event)
    }
}

impl From<identify::Event> for ComposedEvent {
    fn from(event: identify::Event) -> Self {
        ComposedEvent::Identify(event)
    }
}

///builds messaging protocol based on gossip
pub fn build_gossip(local_key: identity::Keypair) -> std::io::Result<Gossipsub> {
    let message_id_fn = |message: &GossipsubMessage| {
        let mut s = DefaultHasher::new();
        message.data.hash(&mut s);
        MessageId::from(s.finish().to_string())
    };

    // Set a custom gossipsub
    let gossipsub_config = gossipsub::GossipsubConfigBuilder::default()
        // This is set to aid debugging by not cluttering the log space
        .heartbeat_interval(Duration::from_secs(10))
        .message_id_fn(message_id_fn)
        .build()
        .expect("Valid config");

    let gossipsub: Gossipsub =
        gossipsub::Gossipsub::new(MessageAuthenticity::Signed(local_key), gossipsub_config)
            .expect("Correct configuration");

    Ok(gossipsub)
}

///builds kademlia behaviour to be use in swarm
pub fn build_kademlia(peer_id: PeerId) -> Kademlia<MemoryStore> {
    let store = MemoryStore::new(peer_id);
    let mut kad_config = KademliaConfig::default();
    kad_config.set_protocol_names(gossip_protocol_name());
    kad_config.set_query_timeout(Duration::from_secs(300));
    kad_config.set_record_filtering(KademliaStoreInserts::FilterBoth);
    // set disjoint_query_paths to true. Ref: https://discuss.libp2p.io/t/s-kademlia-lookups-over-disjoint-paths-in-rust-libp2p/571
    kad_config.disjoint_query_paths(true);
    let kademlia = Kademlia::with_config(peer_id, store, kad_config);
    kademlia
}

///builds ping behaviour to be use in swarm
pub fn build_ping() -> ping::Behaviour {
    ping::Behaviour::new(ping::Config::new())
}

///builds kademlia behaviour to be use in swarm
pub fn build_identify(local_public_key: identity::PublicKey) -> identify::Behaviour {
    identify::Behaviour::new(identify::Config::new(
        "/pdex/id/0.0.1".into(),
        local_public_key,
    ))
}

pub async fn create_tcp_transport(
    local_key_pair: identity::Keypair,
) -> Boxed<(PeerId, StreamMuxerBox)> {
    let transport = {
        let dns_tcp = libp2p::dns::DnsConfig::system(libp2p::tcp::TcpTransport::new(
            libp2p::tcp::GenTcpConfig::new().nodelay(true),
        ))
        .await
        .unwrap();
        let ws_dns_tcp = libp2p::websocket::WsConfig::new(
            libp2p::dns::DnsConfig::system(libp2p::tcp::TcpTransport::new(
                libp2p::tcp::GenTcpConfig::new().nodelay(true),
            ))
            .await
            .unwrap(),
        );
        /*
        Adds a fallback transport that is used when encountering errors while establishing inbound or outbound connections.
        The returned transport will act like self, except that if listen_on or dial return an error then other will be tried.
         */
        dns_tcp.or_transport(ws_dns_tcp)
    };
    transport
        .upgrade(Version::V1)
        .authenticate(libp2p::noise::NoiseAuthenticated::xx(&local_key_pair).unwrap())
        .multiplex(SelectUpgrade::new(
            libp2p::yamux::YamuxConfig::default(),
            MplexConfig::default(),
        ))
        .timeout(Duration::from_secs(20))
        .boxed()
}

#[async_trait]
pub trait MessageHandler: Send + Sync {
    async fn handle_message(
        &self,
        event: GossipsubEvent,
        secret_key: Arc<SecretKey>,
    ) -> Option<(&str, Vec<u8>, bool)>;
}

/// Thea specific gossip network events handler
pub struct TheaEventHandler {
    /// Generic message sender
    pub gossip_sender: Sender<(&'static str, Vec<u8>)>,
    pub gossip_payload_sender: Sender<Payload>,
    pub public_key_map: Arc<HashMap<u32, PublicKey>>,
    pub auth_index: u32,
}

impl Default for TheaEventHandler {
    fn default() -> Self {
        TheaEventHandler {
            gossip_sender: channel(100).0,
            gossip_payload_sender: channel(100).0,
            public_key_map: Arc::new(TheaEventHandler::create_public_key_map()),
            auth_index: 0,
        }
    }
}
impl TheaEventHandler {
    pub fn new(auth_index: u32, gossip_sender: Sender<(&'static str, Vec<u8>)>) -> Self {
        TheaEventHandler {
            gossip_sender: gossip_sender,
            gossip_payload_sender: channel(100).0,
            public_key_map: Arc::new(TheaEventHandler::create_public_key_map()),
            auth_index,
        }
    }

    // This is hardcoded public key map for the purpose of testing the POC
    pub fn create_public_key_map() -> HashMap<u32, PublicKey> {
        let mut public_key_map: HashMap<u32, PublicKey> = HashMap::new();
        for x in 0..10 {
            let mut ikm = [x as u8; 32];
            let sk_1 = SecretKey::key_gen(&ikm, &[]).unwrap();
            let pk_1 = sk_1.sk_to_pk();
            public_key_map.insert(x, pk_1);
        }
        public_key_map
    }

    pub async fn create_aggregate_public_key_from_indexes(
        &self,
        authority_indexes: Vec<u8>,
    ) -> AggregatePublicKey {
        let mut agg_pk: Option<AggregatePublicKey> = None;
        for x in 0..10 {
            if authority_indexes[x as usize] == 1 {
                // Fetch Public Key
                let pk = self.public_key_map[&(x as u32)];
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
}

#[async_trait]
impl MessageHandler for TheaEventHandler {
    async fn handle_message(
        &self,
        event: GossipsubEvent,
        secret_key: Arc<SecretKey>,
    ) -> Option<(&str, Vec<u8>, bool)> {
        match event {
            GossipsubEvent::Message {
                propagation_source: _peer_id,
                message_id: _id,
                message,
            } => {
                log::info!(target:"GossipNode","Received GossipSub Message");
                if let Ok(payload) = serde_json::from_slice::<Payload>(&message.data) {
                    log::debug!(target:"GossipNode","Got new payload: {:?}", payload);
                    // TODO: Reconstruct Signature
                    let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
                    let mut new_payload = payload.clone();
                    let mut recon_signature = payload.signature_part_1;
                    recon_signature.extend(payload.signature_part_2);
                    recon_signature.extend(payload.signature_part_3);

                    let recon_sig = Signature::from_bytes(&recon_signature).unwrap();
                    let mut agg_sig = AggregateSignature::from_signature(&recon_sig);
                    let agg_pk = self
                        .create_aggregate_public_key_from_indexes(payload.authority_index.clone())
                        .await;
                    let err = recon_sig.fast_aggregate_verify_pre_aggregated(
                        false,
                        &payload.msg,
                        dst,
                        &agg_pk.to_public_key(),
                    );

                    log::info!(target:"GossipNode","Signature Verification Completed for Gossip Sub: {:#?}", err );
                    // Verify 100% threshold
                    // TODO this can be improved
                    let mut count: u32 = 0;
                    for x in &payload.authority_index {
                        if *x == 1 as u8 {
                            count += 1;
                        }
                    }
                    if count > 5 {
                        log::info!(target:"Gossip", "Received Majority for this message: {:#?}", String::from_utf8(payload.msg));
                        let payload_bytes = serde_json::to_vec(&new_payload).unwrap();
                        return Some(("thea", payload_bytes, true));
                    }
                    // Broadcast it again
                    if payload.authority_index[self.auth_index as usize] == 0 {
                        let new_payload = Payload::create_new_payload(
                            secret_key,
                            self.auth_index as u8,
                            &new_payload,
                            agg_sig,
                        )
                        .await;
                        let payload_bytes = serde_json::to_vec(&new_payload).unwrap();
                        log::info!(target:"GossipNode","Broadcast same message with new aggregate signature");
                        return Some(("thea", payload_bytes, false));
                    } else {
                        log::info!(target:"GossipNode","Payload already signed, Skipping resigning and broadcasting: {:?}", payload.authority_index);
                    }
                } else {
                    log::debug!(target:"GossipNode","Got some other message");
                }
            }
            _ => log::debug!(target:"GossipNode","Non-message event received"),
        }
        None
    }
}

pub struct TheaNetwork {
    pub id: PeerId,
    pub port: u16,
    pub peers: Arc<AtomicUsize>,
    bootstrapped: Arc<AtomicBool>,
    node_keys: Keypair,
    secret_key: Arc<SecretKey>,
    handler: TheaEventHandler,
    swarm: Arc<Swarm<TheaNetBehaviour>>,
    receiver: Arc<Receiver<(&'static str, Vec<u8>)>>,
}

unsafe impl Send for TheaNetwork {}
unsafe impl Sync for TheaNetwork {}

impl TheaNetwork {
    /// Network constructor.
    /// Panics if provided `node_keys` are incorrect somehow
    /// # Parameters
    /// * id - Identity of the peer for current node
    /// * port - Listening TCP port dedicated for this node
    /// * node_keys - key pair of keys for this node to use for communications
    /// * secret_key - shared `SecretKey` ref for BBS sigs?
    /// * authority_id - identifier for BBS authority set
    /// * g_sender - channel `Sender` for behaviour construction
    /// * receiver - channel `Receiver` as input for gossip sending
    /// # Errors
    /// None
    pub async fn new(
        id: PeerId,
        port: u16,
        node_keys: Keypair,
        secret_key: Arc<SecretKey>,
        authority_id: u32,
        g_sender: Sender<(&'static str, Vec<u8>)>,
        receiver: Receiver<(&'static str, Vec<u8>)>,
    ) -> Box<Self> {
        let transport = create_tcp_transport(node_keys.clone()).await;
        let behaviour = TheaNetBehaviour {
            gossip_sub: build_gossip(node_keys.clone()).expect("Incorrect keys provided"),
            kademlia: build_kademlia(id.clone()),
            identify: build_identify(node_keys.public().clone()),
            ping: build_ping(),
        };
        let swarm = Arc::new(
            SwarmBuilder::new(transport, behaviour, id.clone())
                .executor(Box::new(|fut| {
                    tokio::spawn(fut);
                }))
                .build(),
        );

        Box::new(TheaNetwork {
            id,
            port,
            peers: Arc::new(AtomicUsize::new(0)),
            bootstrapped: Arc::new(AtomicBool::new(false)),
            node_keys,
            secret_key,
            handler: TheaEventHandler::new(authority_id, g_sender),
            swarm,
            receiver: Arc::new(receiver),
        })
    }

    /// Returns `true` if number of all swarm's gossip_sub peers greater or equal to target
    /// # Parameters
    /// * target - number of nodes we expect at least in the gossip sub network
    pub fn have_sufficient_peers(&self, target: usize) -> bool {
        self.peers.load(Ordering::Relaxed) >= target
    }

    /// Runs the network with given topics, seed and boot nodes and explicit peer, if any
    pub async fn run(
        mut self,
        topics: impl AsRef<[String]>,
        seed_nodes: impl AsRef<[String]>,
        boot_nodes: impl AsRef<[String]>,
        explicit_peer: Option<&str>,
        s_sender: Sender<(Vec<u8>)>
    ) -> anyhow::Result<()> {
        log::info!(target:"GossipNode","Our id: {}", &self.id.to_string());
        // subscribing to every interesting topic
        let mut swarm = Arc::get_mut(&mut self.swarm).expect("Failed to get mutable swarm");
        for topic in topics.as_ref() {
            swarm
                .behaviour_mut()
                .gossip_sub
                .subscribe(&Sha256Topic::new(topic))?;
        }

        if let Some(ep) = explicit_peer {
            match ep.parse() {
                Ok(id) => swarm.behaviour_mut().gossip_sub.add_explicit_peer(&id),
                Err(e) => return Err(Error::msg(e.to_string())),
            }
        }

        let str_port = self.port.to_string();
        swarm.listen_on(format!("/ip4/0.0.0.0/tcp/{str_port}").parse()?)?;

        // engage with seed nodes if any
        for node in seed_nodes.as_ref() {
            swarm.dial(Multiaddr::try_from(node.as_ref())?)?;
        }

        // bootstrap kademlia
        for boot_node in boot_nodes.as_ref() {
            let mut address = Multiaddr::try_from(boot_node.as_ref())?;
            let peer_id = match address.pop() {
                Some(Protocol::P2p(hash)) => match PeerId::from_multihash(hash) {
                    Ok(id) => id,
                    // TODO: verify this logic
                    Err(_) => continue,
                },
                // TODO: verify this logic
                _ => continue,
            };
            // inject
            swarm
                .behaviour_mut()
                .kademlia
                .add_address(&peer_id, address.clone());
            swarm.dial(address)?;
            self.bootstrapped.store(true, Ordering::Relaxed);
        }
        if self.bootstrapped.load(Ordering::Relaxed) {
            swarm.behaviour_mut().kademlia.bootstrap()?;
        }

        let inner_sender = self.handler.gossip_sender.clone();
        let inner_sk = self.secret_key.clone();
        let inner_peers = self.peers.clone();
        let auth_index = self.handler.auth_index;
        #[cfg(benchmark)]
        let _h = tokio::spawn(async move {
            log::info!(
                target: "GossipNode",
                "Started sender loop"
            );
            // So that there is sufficient time for peers to connect before publishing GossipSub Message
            while inner_peers.load(Ordering::Relaxed) < 3 {
                log::debug!(
                    target: "GossipNode",
                    "Not enough peers in the network. Sleeping 1 sec"
                );
                tokio::time::sleep(Duration::from_millis(1000)).await;
            }
            /* if inner_b.load(Ordering::Relaxed) {
                // TODO: Create Payload here
                let mut payload = Payload::create_payload(sk.clone(), "thea ping".as_bytes(), auth as u8).await;
                payload.authority_index[auth as usize] = 1;
                let payload_bytes = serde_json::to_vec(&payload).unwrap();
                g_sender
                    .send(("thea", payload_bytes))
                    .await
                    .expect("Failed to send new payload");
            } */
            let in_loop_sender = inner_sender.clone();
            loop {
                log::info!(
                    target: "GossipNode",
                    "Generating and sending random payload"
                );
                let mut line: [u8; 32] = rand::random();
                let mut payload =
                    Payload::create_payload(inner_sk.clone(), &line, auth_index as u8).await;
                payload.authority_index[auth_index as usize] = 1;
                let payload_bytes = serde_json::to_vec(&payload).unwrap();
                in_loop_sender
                    .send(("thea", payload_bytes))
                    .await
                    .expect("Failed to send new payload to pipe");
            }
        });
        // message handling loop
        // FIXME: extract and error handle properly
        let receiver = Arc::get_mut(&mut self.receiver).expect("failed to get mut ref to receiver");
        loop {
            tokio::select! {
                // local node gossip send to network
                r = receiver.recv() => {
                    if let Some((topic, data)) = r {
                        log::info!(target: "GossipNode","Sending new gossip_sub message to the network");
                        if let Err(e) = swarm.behaviour_mut().gossip_sub.publish(Sha256Topic::new(topic), data) {
                            log::error!(target:"GossipNode","Could not GossipSub due to: {:#?}", e);
                        }
                    }
                },
                // network messages from other nodes
                event = swarm.select_next_some() => match event {
                    SwarmEvent::Behaviour(ComposedEvent::Gossipsub(message)) => {
                        let new_payload = self.handler.handle_message(message, self.secret_key.clone()).await;
                        if new_payload.is_some(){
                            if let Some((topic, data, flag)) = new_payload{
                                if flag {
                                    // Forward to substrate runner
                                    s_sender.send((data)).await.unwrap();
                                } else {
                                    if let Err(e) = swarm.behaviour_mut().gossip_sub.publish(Sha256Topic::new(topic), data) {
                                    // log::info!(target:"Blockchain","Fetching Grandpa Authorities");
                                    log::error!(target:"GossipNode","Could not GossipSub due to: {:#?}", e);
                                    }
                                }

                            }
                        }

                    },
                    SwarmEvent::OutgoingConnectionError {peer_id, ..} => if let Some(pid) = peer_id {
                        log::info!(target:"GossipNode","Peer with id {pid} exited.");
                    },
                    SwarmEvent::Behaviour(ComposedEvent::Identify(event)) => match event {
                        identify::Event::Received { peer_id, info } => {
                            for address in info.listen_addrs {
                                swarm.behaviour_mut().kademlia.add_address(&peer_id, address);
                            }
                            log::info!(target:"GossipNode","New peer identification received: {peer_id}");
                            let new_peers = self.peers.load(Ordering::Relaxed) + 1;
                            self.peers.store(new_peers, Ordering::Relaxed);
                        },
                        _ => log::debug!(target:"GossipNode","Other Identify event received? :>")
                    },
                    //TODO: Kademlia events handle
                    SwarmEvent::Behaviour(ComposedEvent::Kademlia(event)) => {
                        log::debug!(target:"GossipNode","Kademlia event received.");
                    },
                    // TODO: Ping event handle
                    SwarmEvent::Behaviour(ComposedEvent::PingEvent(event)) => {
                        log::debug!(target:"GossipNode","Ping event received");
                    },
                    // TODO: implement events handling
                    _ => log::debug!(target:"GossipNode","Got new event from network"),
                }
            }
        }
    }
}

fn random_net_build_inputs(
    buffer: usize,
) -> (
    PeerId,
    u16,
    Keypair,
    SecretKey,
    Sender<(&'static str, Vec<u8>)>,
    Receiver<(&'static str, Vec<u8>)>,
) {
    let (s, r) = channel(buffer);
    let local_key = Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());
    let ikm: [u8; 32] = random();
    let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
    (
        local_peer_id,
        portpicker::pick_unused_port()
            .expect("no free ports")
            .into(),
        local_key,
        sk,
        s,
        r,
    )
}

// async fn build_and_run_random_node(boot_nodes: Vec<PeerId>, next_id: u32) {
//     let boot_nodes_addr: Vec<String> = boot_nodes
//         .into_iter()
//         .map(|id| format!("/ip4/127.0.0.1/tcp/26000/p2p/{}", id.to_string()))
//         .collect();
//     let (id, p, kp, sk, s, r) = random_net_build_inputs(100);
//     let net = TheaNetwork::new(id, p, kp, Arc::new(sk), next_id, s, r).await;
//     net.run(vec!["thea".to_string()], vec![], boot_nodes_addr, None)
//         .await
//         .expect("Cluster node failed")
// }
//
// async fn build_boot_node(kp: Keypair) -> Box<TheaNetwork> {
//     use crate::NetworkWorkerParams;
//     let (g_sender, g_receive) = channel(100);
//     let auth = 0;
//     let auth_index = Arc::new(auth);
//     let mut ikm = [auth as u8; 32];
//     let sk_1 = SecretKey::key_gen(&ikm, &[]).unwrap();
//     let local_peer_id = PeerId::from(kp.public());
//     TheaNetwork::new(
//         local_peer_id,
//         26000,
//         kp,
//         Arc::new(sk_1),
//         *auth_index,
//         g_sender,
//         g_receive,
//     )
//     .await
// }
//
// #[tokio::test]
// async fn one_k_peers() -> anyhow::Result<()> {
//     env_logger::init();
//     let local_key = Keypair::generate_ed25519();
//     let bn_id = PeerId::from(local_key.public());
//     let mut other_nodes = FuturesUnordered::new();
//     // boot node run
//     tokio::spawn(async move {
//         let boot_node = build_boot_node(local_key).await;
//         boot_node
//             .run(vec!["thea".to_string()], vec![], vec![], None)
//             .await
//             .expect("boot node failed");
//     });
//     // 999 nodes in
//     for id in 0..10 {
//         other_nodes.push(build_and_run_random_node(vec![bn_id.clone()], id));
//     }
//     let timer = tokio::time::sleep(Duration::from_secs(60));
//     tokio::select! {
//         _t = timer => {
//             log::info!(target: "GossipNode", "Timer is done");
//             Ok(())
//             },
//         _r = other_nodes.for_each(|_| async move {}) => Err(anyhow::Error::msg("Some node failed before timer"))
//     }
// }
