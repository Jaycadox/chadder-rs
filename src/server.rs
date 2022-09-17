use crate::shared::{self, LuaLoader, MessagePacket, Packet, COMPRESSION};
use anyhow::anyhow;
use async_net::SocketAddr;
use log::{debug, info, warn};
use mlua::prelude::LuaFunction;
use mlua::{chunk, Value};
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
    peers: Arc<Mutex<Vec<NetPeer>>>,
    packet: Packet,
    lua: Arc<Mutex<LuaLoader>>,
) -> anyhow::Result<()> {
    if let Packet::Message(pack) = &packet {
        if !peers.lock().await.get(index).unwrap().has_profile() {
            return Err(anyhow::Error::msg("Message packet without profile"));
        }
        let content = pack.content.trim().to_owned();
        if content.is_empty() {
            return Ok(());
        }

        let mut should_cancel = false;
        let name = peers.lock().await.get(index).unwrap().name();
        lua.lock().await.scripts.iter_mut().for_each(|l| {
            let ctx = l.lua.create_table().unwrap();
            ctx.set("username", name.clone()).unwrap();
            ctx.set("message", content.clone()).unwrap();
            l.lua
                .load(chunk! {
                    __ret = false
                    for k,v in pairs(__on_message_callbacks) do
                        if v($ctx) == true then
                            __ret = true
                        end
                    end
                })
                .exec()
                .unwrap();
            let ret = l.lua.globals().get::<&str, Value>("__ret").unwrap();
            if let Value::Boolean(ret) = ret {
                if ret {
                    should_cancel = true;
                }
            }
        });
        if should_cancel {
            return Ok(());
        }
        let name = peers.lock().await.get(index).unwrap().name();
        info!(
            "[{}]: {}",
            peers.lock().await.get(index).unwrap().name(),
            content
        );
        for p in peers.lock().await.iter_mut() {
            p.send_packet(Packet::Message(MessagePacket {
                sender: name.clone(),
                content: content.clone(),
            }));
        }
    } else if let Packet::RequestEncryption(pack) = &packet {
        if let Ok(key) = RsaPublicKey::from_public_key_pem(&*pack.public_key) {
            peers.lock().await.get_mut(index).unwrap().public_key = Some(key.clone());
            let x_key = xchacha20poly1305_ietf::gen_key();
            let x_nonce = xchacha20poly1305_ietf::gen_nonce();

            let encoded_key = bincode::serialize(&x_key)?;
            let encoded_nonce = bincode::serialize(&x_nonce)?;

            let encrypted_key;
            let encrypted_nonce;
            {
                let mut rng = rand::thread_rng();
                encrypted_key = key.encrypt(
                    &mut rng,
                    PaddingScheme::new_pkcs1v15_encrypt(),
                    &encoded_key,
                )?;
                encrypted_nonce = key.encrypt(
                    &mut rng,
                    PaddingScheme::new_pkcs1v15_encrypt(),
                    &encoded_nonce,
                )?;
            }

            let res = xchacha20poly1305_ietf::seal(b"chadder", None, &x_nonce, &x_key);
            peers
                .lock()
                .await
                .get_mut(index)
                .unwrap()
                .send_packet(Packet::EncryptionEstablishKey((
                    encrypted_key,
                    encrypted_nonce,
                    res,
                )));
            peers.lock().await.get_mut(index).unwrap().key = Some(x_key);
            peers.lock().await.get_mut(index).unwrap().nonce = Some(x_nonce);
            debug!(
                "Client ({}) has established an encrypted connection.",
                peers.lock().await.get(index).unwrap().interface.address
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
    lua: Arc<Mutex<LuaLoader>>,
) -> anyhow::Result<()> {
    let mut data = Vec::from(data);
    {
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
    }
    {
        if COMPRESSION {
            data = match miniz_oxide::inflate::decompress_to_vec_with_limit(&*data, 4096) {
                Ok(bytes) => bytes,
                Err(_) => return Err(anyhow!("Unable to decompress packet")),
            };
        }
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
            let count;
            {
                count = connections.lock().await.len();
            }
            for i in 0..count {
                {
                    if connections.lock().await[i].name().trim() == pack.name {
                        return Err(anyhow!("Username taken"));
                    }
                    if connections.lock().await[i].interface.address != address {
                        continue;
                    }
                }

                let prof;
                {
                    prof = connections.lock().await[i].generate_profile(pack.name.clone());
                }
                if let Some(prof) = prof {
                    {
                        debug!(
                            "Client ({}) generated profile: {:?}",
                            connections.lock().await[i].interface.address,
                            prof
                        );
                    }
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
            lua.lock().await.scripts.iter_mut().for_each(|l| {
                let name = pack.name.clone();
                l.lua
                    .load(chunk! {
                        if __on_connection_callbacks == nil then __on_connection_callbacks = {} end
                        for k,v in pairs(__on_connection_callbacks) do
                            v($name)
                        end
                    })
                    .exec()
                    .unwrap();
            });
        }
        _ => {
            let mut s_index = 0;
            {
                let mut r_peers = connections.lock().await;

                for (index, connection) in r_peers.iter_mut().enumerate() {
                    if connection.interface.address == address {
                        s_index = index;
                        break;
                    }
                }
            }

            if let Err(e) = handle_packet(s_index, Arc::clone(&connections), pack, lua).await {
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
    lua: Arc<Mutex<LuaLoader>>,
) -> Result<(), Box<dyn Error>> {
    loop {
        let mut buffer = [0; 1024];
        match read.read(&mut buffer).await {
            Ok(n) if n == 0 => break,
            Ok(n) => {
                match handle_raw_packet(
                    &buffer[0..n],
                    address,
                    Arc::clone(&connections),
                    Arc::clone(&lua),
                )
                .await
                {
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
    let lua = Arc::new(Mutex::new(LuaLoader::new()));

    if std::path::Path::new("scripts/").exists() {
        for f in std::fs::read_dir("scripts/").unwrap() {
            let f = f.unwrap();
            let name = f.file_name();
            let name = name.to_str().unwrap();
            debug!("[LUA] Loading script: {name}");
            let content = std::fs::read_to_string(f.path()).unwrap();
            lua.lock().await.content(&content);
        }
    }

    lua.lock().await.content("server.on_connection(function(username) server.send_message(username, \"System\", \"Welcome to the server!\") end)");
    lua.lock().await.scripts.iter_mut().for_each(|l| {
        l.lua
            .load(chunk! {
                if __on_server_callbacks == nil then __on_server_callbacks = {} end
                for k,v in pairs(__on_server_callbacks) do
                    v()
                end
            })
            .exec()
            .unwrap();
    });

    let server = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", PORT)).await?;
    let connections: Arc<Mutex<Vec<NetPeer>>> = Arc::new(Mutex::new(vec![]));
    let connections_1 = Arc::clone(&connections);

    for l in lua.lock().await.scripts.iter_mut() {
        let connections_l = Arc::clone(&connections);
        let server = l.lua.create_table().unwrap();
        let send_message = l
            .lua
            .create_function(
                move |_, (username, sender, message): (String, String, String)| {
                    for ctn in futures::executor::block_on(connections_l.lock()).iter_mut() {
                        if ctn.name() != username {
                            continue;
                        }
                        ctn.send_packet(Packet::Message(MessagePacket {
                            sender,
                            content: message,
                        }));
                        return Ok(Value::Boolean(true));
                    }
                    Ok(Value::Boolean(false))
                },
            )
            .unwrap();
        server.set("send_message", send_message).unwrap();
        let on_connection = l
            .lua
            .create_function(move |l, callback: LuaFunction| {
                l.load(chunk! {
                    if __on_connection_callbacks == nil then __on_connection_callbacks = {} end
                    __on_connection_callbacks[#__on_connection_callbacks+1] = $callback
                })
                .exec()
                .unwrap();
                Ok(())
            })
            .unwrap();
        server.set("on_connection", on_connection).unwrap();
        l.lua.globals().set("server", server).unwrap();
    }
    for sc in lua.lock().await.scripts.iter_mut() {
        sc.start();
    }
    debug!("Server bound on port: {}", PORT);
    while let Ok((stream, address)) = server.accept().await {
        let addr_c = address;
        info!("Connection with peer established: {}", addr_c.clone());
        let (read, write) = tokio::io::split(stream);
        connections_1.lock().await.push(NetPeer::new(address));
        let connections_2 = Arc::clone(&connections_1);
        let connections_3 = Arc::clone(&connections_1);
        let connections_4 = Arc::clone(&connections_1);
        let lua_1 = Arc::clone(&lua);
        tokio::spawn(async move {
            let error =
                match handle_connection(read, address, connections_2, Arc::clone(&lua_1)).await {
                    Ok(_) => "lost connection".to_string(),
                    Err(e) => format!("{:?}", e),
                };
            info!("Client ({}) disconnected: {}", addr_c, error);
            for connection in futures::executor::block_on(connections_4.lock()).iter_mut() {
                if connection.interface.address == address {
                    connection.send_packet(Packet::Message(MessagePacket {
                        sender: "System".to_owned(),
                        content: format!("You have lost connection: {}", error),
                    }));
                }
            }
            futures::executor::block_on(connections_4.lock())
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
