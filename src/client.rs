use std::io;
use tokio::io::{ReadHalf, WriteHalf, AsyncWriteExt};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use rsa::PaddingScheme;
use rsa::pkcs1::LineEnding;
use rsa::pkcs8::EncodePublicKey;
use tokio::net::{TcpStream};
use crate::shared;
use tokio::io::{AsyncReadExt};
use crate::shared::{COMPRESSION, EncryptionInfo, Packet};
use sodiumoxide::crypto::aead::xchacha20poly1305_ietf;

const PORT: u16 = 9000;
const ENCRYPTION: bool = true;

type MessageReceiveCallback = fn(String, String);

pub struct Client {
    message_receive: Option<MessageReceiveCallback>,
    message_queue: Vec<Vec<u8>>,
    username: String,
    key: Option<xchacha20poly1305_ietf::Key>,
    nonce: Option<xchacha20poly1305_ietf::Nonce>,
    ip: String
}

impl Client {
    pub fn on_message_receive(&mut self, c: MessageReceiveCallback) {
        self.message_receive = Some(c);
    }
    pub fn send_message(&mut self, content: String) {
        self.send(Packet::Message(shared::MessagePacket {
            sender: "System".to_owned(),
            content,
        }));
    }
    pub fn send(&mut self, packet: Packet) {
        self.message_queue.push(shared::serialize(&packet).unwrap());
    }
    fn message_received(&mut self, sender: String, content: String, allow_client: bool) {
        if sender == "Client" && !allow_client {
            return;
        }
        if let Some(func) = self.message_receive {
            func(sender, content);
        }
    }

    pub fn new(username: String, ip: String) -> Self {
        Client {
            message_receive: None,
            message_queue: vec!(),
            username, key: None, nonce: None, ip
        }
    }

    fn handle_raw_packet(this: Arc<Mutex<Self>>, data: &[u8], encryption: Arc<Mutex<EncryptionInfo>>) -> Result<(), Box<dyn std::error::Error>> {
        let mut data = Vec::from(data);
        {
            let c = this.lock().unwrap();
            if let Some(key) = &c.key {
                if let Some(nonce) = &c.nonce {
                    data = xchacha20poly1305_ietf::open(&data, None, nonce, key).unwrap();
                }
            }
        }
        if COMPRESSION {
            data = match miniz_oxide::inflate::decompress_to_vec_with_limit(&*data, 4096) {
                Ok(bytes) => bytes,
                Err(_) => return Err("Unable to decompress packet".into()),
            };
        }

        let pack = match shared::deserialize(&data) {
            Some(pack) => pack,
            None => {
                return Err(format!("Could not deserialize packet! ({} bytes)", data.len()).into());
            }
        };
        if let Packet::Message(pack) = pack {
            this.lock().unwrap().message_received(pack.sender.clone(), pack.content.clone(), false);
            println!("{}: {}", pack.sender, pack.content);
        } else if let Packet::EncryptionEstablishKey((key, nonce, test)) = pack {
            let key = match encryption.lock()
                .unwrap().private.decrypt(PaddingScheme::new_pkcs1v15_encrypt(), &key) {
                Ok(key) => key,
                Err(_) => return Err("Couldn't decrypt key".into())
            };
            let nonce = match encryption.lock()
                .unwrap().private.decrypt(PaddingScheme::new_pkcs1v15_encrypt(), &nonce) {
                Ok(nonce) => nonce,
                Err(_) => return Err("Couldn't decrypt nonce".into())
            };

            let key = match bincode::deserialize::<xchacha20poly1305_ietf::Key>(&key) {
                Ok(key) => key,
                Err(_) => return Err("Couldn't deserialize key".into())
            };
            let nonce = match bincode::deserialize::<xchacha20poly1305_ietf::Nonce>(&nonce) {
                Ok(nonce) => nonce,
                Err(_) => return Err("Couldn't deserialize nonce".into())
            };
            let res = match xchacha20poly1305_ietf::open(&test, None, &nonce, &key) {
                Ok(r) => r,
                Err(_) => return Err("Couldn't decrypt test string".into())
            };
            if String::from_utf8_lossy(&*res) != "chadder" {
                return Err("Could not verify encryption with server".into())
            }
            this.lock().unwrap().key = Some(key);
            this.lock().unwrap().nonce = Some(nonce);
            this.lock().unwrap().message_received("Client".to_string(),
                                                  "This connection is using end-to-end encryption.".to_string(), true);
            let name = this.lock().unwrap().username.clone();
            this.lock().unwrap().send(Packet::Connection(shared::ConnectionPacket {
                name,
                secret: 46
            }));
        }

        Ok(())
    }

    async fn handle_connection(this: Arc<Mutex<Self>>, mut read: ReadHalf<TcpStream>, encryption: Arc<Mutex<EncryptionInfo>>) -> Result<(), Box<dyn std::error::Error>> {
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        if ENCRYPTION {
            this.lock().unwrap().send(Packet::RequestEncryption(shared::RequestEncryptionPacket {
                public_key: encryption.lock().unwrap().public.clone().to_public_key_pem(LineEnding::CR).unwrap()
            }));
        } else {
            let name = this.lock().unwrap().username.clone();
            this.lock().unwrap().send(Packet::Connection(shared::ConnectionPacket {
                name,
                secret: 46
            }));
        }


        loop {
            let enc = Arc::clone(&encryption);
            let mut buffer = [0; 1024];
            match read.read(&mut buffer).await {
                Ok(n) if n == 0 => {
                    return Err("Connection to server lost".into());
                },
                Ok(n) => {
                    match Client::handle_raw_packet(Arc::clone(&this), &buffer[0..n], enc) {
                        Ok(_) => {},
                        Err(err) => {
                            println!("Disconnecting from server: {:?}", err);
                            return Err(format!("{:?}", err).into());
                        }
                    }
                }
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                    continue;
                },
                Err(err) => {
                    return Err(Box::new(err));
                }
            }
        }
    }
    async fn handle_connection_writer(enc: Arc<Mutex<Self>>, write: &mut WriteHalf<TcpStream>) -> bool {
        let key = enc.lock().unwrap().key.clone();
        let nonce = enc.lock().unwrap().nonce;
        for message in enc.lock().unwrap().message_queue.clone() {
            let mut message = message;
            if COMPRESSION {
                message = miniz_oxide::deflate::compress_to_vec(&message, 6);
            }
            if let Some(key) = &key {
                if let Some(nonce) = &nonce {
                    message = xchacha20poly1305_ietf::seal(&message, None, nonce, key);
                }
            }
            if let Err(_) = write.write(&message).await { return false };
        }
        true
    }
    pub async fn start(this: Arc<Mutex<Self>>) -> Result<(), io::Error> {
        let encryption: Arc<Mutex<EncryptionInfo>> = Arc::new(Mutex::new(EncryptionInfo::new()));
        let encryption_1 = Arc::clone(&encryption);
        let this_2 = Arc::clone(&this);
        let addr: SocketAddr = format!("{}:{}", this.lock().unwrap().ip, PORT).parse().unwrap();
        let stream = TcpStream::connect(addr).await?;
        while let Err(_err) = stream.peer_addr() {}
        println!("Client: connected");
        let (read, mut write) = tokio::io::split(stream);
        tokio::spawn(async move {
            println!("Disconnected from server: {:?}", Client::handle_connection(this_2, read, encryption_1).await);
        });

        loop {
            let this_4 = Arc::clone(&this);
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            {
                if !Client::handle_connection_writer(this_4,&mut write).await {
                    break;
                }
                this.lock().unwrap().message_queue.clear();
            }
        }
        Ok(())
        // loop {
        //     let ready = stream.ready(Interest::READABLE | Interest::WRITABLE).await?;
        //     if true {
        //         
        //         let mut data = vec![0; 1024];
        //         match stream.try_read(&mut data) {
        //             Ok(n) if n == 0 => break,
        //             Ok(_) => {
        //                 // got data
        //                 println!("Got data: {:?}", data);
        //             }
        //             Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
        //             Err(e) => return Err(e.into())
        //         }
        //     }
        //     if ready.is_writable() {
        //         for pack in &this.lock().unwrap().message_queue {
        //             match stream.try_write(pack) {
        //                 Ok(_) => {
        //                 }
        //                 Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
        //                     continue
        //                 }
        //                 Err(e) => {
        //                     return Err(e.into());
        //                 }
        //             }
        //         }
        //         this.lock().unwrap().message_queue.clear();
        //     }
        // }
        // println!("Connected to: {}", format!("127.0.0.1:{}", PORT));
        // let data = &shared::serialize(&shared::Packet::Connection(ConnectionPacket {
        //         name: this.lock().unwrap().username.clone(),
        //         secret: 49
        // })).unwrap()[..];
        // {
        //     let mut client = this.lock().unwrap();
        //     let stream = client.connection.as_mut().unwrap();
        //     stream.write_all(data).await?;
        // }
// 
        // loop {
        //     let mut received_data = vec![0; 4096];
        //     let len = test.borrow_mut().read(&mut received_data).await?;
        //     this.lock().unwrap().message_received(format!("{:?}", received_data))
        // }
    }
}

