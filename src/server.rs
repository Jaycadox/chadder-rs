use crate::shared::{self, MessagePacket, Packet, COMPRESSION};
use anyhow::anyhow;
use async_net::SocketAddr;
use log::{debug, info, warn};
use rsa::pkcs8::DecodePublicKey;
use rsa::{PaddingScheme, PublicKey, RsaPublicKey};
use sodiumoxide::crypto::aead::xchacha20poly1305_ietf;
use std::error::Error;
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
extern crate log;

// const SERVER: Token = Token(0);
const PORT: u16 = 9000;

async fn handle_packet(
    index: usize,
    mut peers: Vec<&mut NetPeer>,
    packet: Packet,
) -> anyhow::Result<()> {
    let peer = &mut peers[index].clone();
    if let Packet::Message(pack) = &packet {
        if !peer.has_profile() {
            return Err(anyhow::Error::msg("Message packet without profile"));
        }
        let content = pack.content.trim().to_owned();
        if content.is_empty() {
            return Ok(());
        }
        info!("[{}]: {}", peer.name(), content);
        for p in peers {
            p.send_packet(Packet::Message(MessagePacket {
                sender: peer.name(),
                content: content.clone(),
            }));
        }
    } else if let Packet::RequestEncryption(pack) = &packet {
        if let Ok(key) = RsaPublicKey::from_public_key_pem(&*pack.public_key) {
            peers[index].public_key = Some(key.clone());
            let x_key = xchacha20poly1305_ietf::gen_key();
            let x_nonce = xchacha20poly1305_ietf::gen_nonce();

            let encoded_key = bincode::serialize(&x_key)?;
            let encoded_nonce = bincode::serialize(&x_nonce)?;
            let mut rng = rand::thread_rng();
            let encrypted_key = key.encrypt(
                &mut rng,
                PaddingScheme::new_pkcs1v15_encrypt(),
                &encoded_key,
            )?;
            let encrypted_nonce = key.encrypt(
                &mut rng,
                PaddingScheme::new_pkcs1v15_encrypt(),
                &encoded_nonce,
            )?;
            let res = xchacha20poly1305_ietf::seal(b"chadder", None, &x_nonce, &x_key);
            peers[index].send_packet(Packet::EncryptionEstablishKey((
                encrypted_key,
                encrypted_nonce,
                res,
            )));
            peers[index].key = Some(x_key);
            peers[index].nonce = Some(x_nonce);
            debug!(
                "Client ({}) has established an encrypted connection.",
                peers[index].interface.address
            );
        } else {
            return Err(anyhow::anyhow!(
                "Client could not specify a valid encryption key!"
            ));
        }
    }
    anyhow::Ok(())
}

async fn handle_raw_packet(
    data: &[u8],
    address: SocketAddr,
    connections: Arc<Mutex<Vec<NetPeer>>>,
) -> anyhow::Result<()> {
    let mut data = Vec::from(data);

    for connection in connections.lock().await.iter() {
        if connection.interface.address != address {
            continue;
        }
        if let Some(key) = &connection.key {
            if let Some(nonce) = &connection.nonce {
                data = match xchacha20poly1305_ietf::open(&data, None, nonce, key) {
                    Ok(data) => data,
                    Err(_) => return Err(anyhow!("Unable to decrypt incoming packet")),
                };
            }
        }
        break;
    }
    if COMPRESSION {
        data = match miniz_oxide::inflate::decompress_to_vec_with_limit(&*data, 4096) {
            Ok(bytes) => bytes,
            Err(_) => return Err(anyhow!("Unable to decompress packet")),
        };
    }
    let pack = match shared::deserialize(&data) {
        Some(pack) => pack,
        None => {
            return Err(anyhow!(
                "Could not deserialize packet! ({} bytes)",
                data.len()
            ));
        }
    };
    match pack {
        Packet::Connection(pack) => {
            if pack.secret != 46 {
                return Err(anyhow!("Invalid connection secret"));
            }
            if pack.name.trim() == "System" || pack.name.trim() == "Client" {
                return Err(anyhow!("Illegal username"));
            }
            for connection in connections.lock().await.iter_mut() {
                if connection.name().trim() == pack.name {
                    return Err(anyhow!("Username taken"));
                }
                if connection.interface.address != address {
                    continue;
                }
                if let Some(prof) = &connection.generate_profile(pack.name.clone()) {
                    debug!(
                        "Client ({}) generated profile: {:?}",
                        connection.interface.address, prof
                    );
                } else {
                    return Err(anyhow!("Duplicate connection packet"));
                };
                break;
            }
            for connection in connections.lock().await.iter_mut() {
                connection.send_packet(Packet::Message(MessagePacket {
                    sender: "System".to_owned(),
                    content: format!("{} joined!", pack.name).to_owned(),
                }));
            }
        }
        _ => {
            let mut r_peers = connections.lock().await;
            let mut peers = vec![];
            let mut s_index = 0;
            for (index, connection) in r_peers.iter_mut().enumerate() {
                if connection.interface.address == address {
                    s_index = index;
                }
                peers.push(connection);
            }
            if let Err(e) = handle_packet(s_index, peers, pack).await {
                return Err(anyhow::anyhow!(e));
            }
        }
    }

    Ok(())
}

async fn handle_connection_writer(
    mut write: WriteHalf<TcpStream>,
    address: SocketAddr,
    connections: Arc<Mutex<Vec<NetPeer>>>,
) -> Result<(), Box<dyn Error>> {
    loop {
        for connection in connections.lock().await.iter_mut() {
            if connection.interface.address != address {
                continue;
            }
            for (packet, encrypt) in &connection.interface.queue {
                let mut packet = packet.clone();
                if COMPRESSION {
                    packet = miniz_oxide::deflate::compress_to_vec(&packet, 6);
                }
                if *encrypt {
                    if let Some(key) = &connection.key {
                        if let Some(nonce) = &connection.nonce {
                            packet =
                                xchacha20poly1305_ietf::seal(&packet, None, nonce, key).clone();
                        }
                    }
                }

                match write.write(&packet).await {
                    Ok(n) if n == 0 => break,
                    Ok(_) => {}
                    Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(_err) => {
                        warn!("(Server) packet write routine failed!");
                        return Ok(());
                    }
                }
            }
            connection.interface.queue.clear();
        }
        tokio::task::yield_now().await;
    }
}

async fn handle_connection(
    mut read: ReadHalf<TcpStream>,
    address: SocketAddr,
    connections: Arc<Mutex<Vec<NetPeer>>>,
) -> Result<(), Box<dyn Error>> {
    loop {
        let mut buffer = [0; 1024];
        match read.read(&mut buffer).await {
            Ok(n) if n == 0 => break,
            Ok(n) => {
                match handle_raw_packet(&buffer[0..n], address, Arc::clone(&connections)).await {
                    Ok(_) => {}
                    Err(err) => {
                        warn!("Dropping client {} ({:?})", &address, err);
                        return Err(format!("{:?}", err).into());
                    }
                }
            }
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(err) => {
                return Err(Box::new(err));
            }
        }
    }
    Ok(())
}
#[derive(Clone, Debug)]
struct SocketInterface {
    address: SocketAddr,
    queue: Vec<(Vec<u8>, bool)>,
}

#[derive(Clone, Debug)]
struct NetPeer {
    interface: SocketInterface,
    public_key: Option<RsaPublicKey>,
    nonce: Option<xchacha20poly1305_ietf::Nonce>,
    key: Option<xchacha20poly1305_ietf::Key>,
    profile: Option<PeerProfile>,
}

impl NetPeer {
    fn new(address: SocketAddr) -> Self {
        NetPeer {
            interface: SocketInterface::new(address),
            profile: None,
            public_key: None,
            nonce: None,
            key: None,
        }
    }
    fn send_packet(&mut self, packet: Packet) -> bool {
        let serialized_pack = match shared::serialize(&packet) {
            Some(pack) => pack,
            None => {
                return false;
            }
        };
        self.interface.queue.push((
            serialized_pack,
            !matches!(packet, Packet::EncryptionEstablishKey(_)),
        ));
        true
    }
    fn generate_profile(&mut self, username: String) -> Option<PeerProfile> {
        if self.profile.is_some() {
            return None;
        }
        let prof = Some(PeerProfile {
            username: username.trim().to_owned(),
        });
        self.profile = prof.clone();
        Some(prof.unwrap())
    }
    fn has_profile(&self) -> bool {
        matches!(self.profile, Some(_))
    }
    fn name(&self) -> String {
        if let Some(profile) = &self.profile {
            return profile.username.clone();
        }
        format!("{}", self.interface.address)
    }
}

#[derive(Clone, Debug)]
struct PeerProfile {
    username: String,
}

impl SocketInterface {
    fn new(address: SocketAddr) -> Self {
        SocketInterface {
            address,
            queue: Vec::new(),
        }
    }
}

pub async fn start() -> io::Result<()> {
    fern::Dispatch::new()
        // Perform allocation-free log formatting
        .format(|out, message, record| {
            out.finish(format_args!(
                "{} [{}] [{}] {}",
                chrono::Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
                record.target(),
                record.level(),
                message
            ))
        })
        // Add blanket level filter -
        .level(log::LevelFilter::Debug)
        // - and per-module overrides
        // Output to stdout, files, and other Dispatch configurations
        .chain(std::io::stdout())
        // Apply globally
        .apply()
        .unwrap();
    info!("Chadder-rs: pre alpha 0.1");

    let server = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", PORT)).await?;
    let connections: Arc<Mutex<Vec<NetPeer>>> = Arc::new(Mutex::new(vec![]));
    let connections_1: Arc<Mutex<Vec<NetPeer>>> = Arc::clone(&connections);

    debug!("Server bound on port: {}", PORT);
    while let Ok((stream, address)) = server.accept().await {
        let addr_c = address;
        info!("Connection with peer established: {}", addr_c.clone());
        let (read, write) = tokio::io::split(stream);
        connections_1.lock().await.push(NetPeer::new(address));
        let connections_2 = Arc::clone(&connections_1);
        let connections_3 = Arc::clone(&connections_1);
        let connections_4 = Arc::clone(&connections_1);
        tokio::spawn(async move {
            let error = match handle_connection(read, address, connections_2).await {
                Ok(_) => "lost connection".to_string(),
                Err(e) => format!("{:?}", e),
            };
            info!("Client ({}) disconnected: {}", addr_c, error);
            for connection in connections_4.lock().await.iter_mut() {
                if connection.interface.address == address {
                    connection.send_packet(Packet::Message(MessagePacket {
                        sender: "System".to_owned(),
                        content: format!("You have lost connection: {}", error),
                    }));
                }
            }
            connections_4
                .lock()
                .await
                .retain(|f| f.interface.address != address);
        });
        tokio::spawn(async move {
            debug!(
                "{:?}",
                handle_connection_writer(write, address, connections_3).await
            );
        });
    }
    Ok(())
}
