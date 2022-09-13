use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Serialize, Deserialize};
use sodiumoxide::crypto::aead::xchacha20poly1305_ietf;

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
    pub secret: u8
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MessagePacket {
    pub sender: String,
    pub content: String,
}

pub fn serialize(packet: &Packet) -> Option<Vec<u8>> {
    match bincode::serialize(packet) {
        Ok(out) => Some(out),
        _ => None
    }
}

pub fn deserialize(packet: &[u8]) -> Option<Packet> {
    match bincode::deserialize(packet) {
        Ok(out) => Some(out),
        _ => None
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
            key: xchacha20poly1305_ietf::gen_key()
        }
    }

}