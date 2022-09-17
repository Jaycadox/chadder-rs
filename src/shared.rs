use log::error;
use mlua::prelude::LuaFunction;
use mlua::{chunk, Lua};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::aead::xchacha20poly1305_ietf;

pub const COMPRESSION: bool = true;

#[derive(Serialize, Deserialize, Debug)]
pub enum Packet {
    Connection(ConnectionPacket),
    Message(MessagePacket),
    RequestEncryption(RequestEncryptionPacket),
    EncryptionEstablishKey((Vec<u8>, Vec<u8>, Vec<u8>)),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RequestEncryptionPacket {
    pub public_key: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ConnectionPacket {
    pub name: String,
    pub secret: u8,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MessagePacket {
    pub sender: String,
    pub content: String,
}

pub fn serialize(packet: &Packet) -> Option<Vec<u8>> {
    match bincode::serialize(packet) {
        Ok(out) => Some(out),
        _ => None,
    }
}

pub fn deserialize(packet: &[u8]) -> Option<Packet> {
    match bincode::deserialize(packet) {
        Ok(out) => Some(out),
        _ => None,
    }
}

#[derive(Debug)]
pub struct EncryptionInfo {
    pub public: RsaPublicKey,
    pub private: RsaPrivateKey,
    pub nonce: xchacha20poly1305_ietf::Nonce,
    pub key: xchacha20poly1305_ietf::Key,
}

impl EncryptionInfo {
    pub fn new() -> Self {
        // let c = xchacha20poly1305_ietf::seal(b"test", None, &n, &k);
        let mut rng = rand::thread_rng();
        let bits = 2048;
        let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let public_key = RsaPublicKey::from(&private_key);
        EncryptionInfo {
            public: public_key,
            private: private_key,
            nonce: xchacha20poly1305_ietf::gen_nonce(),
            key: xchacha20poly1305_ietf::gen_key(),
        }
    }
}
pub struct LuaScript {
    pub lua: Box<Lua>,
    content: String,
}

unsafe impl Send for LuaScript {}

impl LuaScript {
    fn new(content: String) -> LuaScript {
        let lua = Lua::new();
        LuaScript {
            lua: Box::new(lua),
            content,
        }
    }
    fn setup_env(&mut self) {
        let events = self.lua.create_table().unwrap();
        {
            let on_server_callbacks = self.lua.create_table().unwrap();
            self.lua
                .globals()
                .set("__on_server_callbacks", on_server_callbacks)
                .unwrap();
            let on_server = self
                .lua
                .create_function(|lua, callback: LuaFunction| {
                    lua.load(chunk! {
                        __on_server_callbacks[#__on_server_callbacks+1] = $callback
                    })
                    .exec()
                    .unwrap();
                    Ok(())
                })
                .unwrap();
            events.set("on_server", on_server).unwrap();
        }
        {
            let on_client_callbacks = self.lua.create_table().unwrap();
            self.lua
                .globals()
                .set("__on_client_callbacks", on_client_callbacks)
                .unwrap();
            let on_client = self
                .lua
                .create_function(|lua, callback: LuaFunction| {
                    lua.load(chunk! {
                        __on_client_callbacks[#__on_client_callbacks+1] = $callback
                    })
                    .exec()
                    .unwrap();
                    Ok(())
                })
                .unwrap();
            events.set("on_client", on_client).unwrap();
        }
        {
            let on_message_callbacks = self.lua.create_table().unwrap();
            self.lua
                .globals()
                .set("__on_message_callbacks", on_message_callbacks)
                .unwrap();
            let on_message = self
                .lua
                .create_function(|lua, callback: LuaFunction| {
                    lua.load(chunk! {
                        __on_message_callbacks[#__on_message_callbacks+1] = $callback
                    })
                    .exec()
                    .unwrap();
                    Ok(())
                })
                .unwrap();
            events.set("on_message", on_message).unwrap();
        }
        self.lua.globals().set("events", events).unwrap();
    }
    pub fn start(&mut self) {
        if let Err(e) = self.lua.load(&self.content).exec() {
            error!("Lua Environment: {e}");
        };
    }
}

pub struct LuaLoader {
    pub scripts: Vec<LuaScript>,
}
impl LuaLoader {
    pub fn new() -> Self {
        LuaLoader { scripts: vec![] }
    }
    pub fn content(&mut self, content: &str) {
        //let content = std::fs::read_to_string(file_name).unwrap();
        let mut script = LuaScript::new(content.to_owned());
        script.setup_env();
        self.scripts.push(script);
    }
}
