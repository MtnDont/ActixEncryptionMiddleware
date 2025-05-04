use actix_http::header::{HeaderMap, HeaderName, HeaderValue};
use actix_web::{
    body::{BodySize, MessageBody},
    dev::{self, Service, ServiceRequest, ServiceResponse, Transform},
    web::{Bytes, BytesMut},
    error, Error,
};
use base64::prelude::*;
use chacha20poly1305::{
    aead::Aead,
    KeyInit, XChaCha20Poly1305, XNonce
};
use rand::{rngs::OsRng, RngCore};
use std::{
    fs::File,
    future::{ready, Future, Ready},
    io::Read,
    marker::PhantomData,
    path::{Path, PathBuf},
    pin::Pin,
    task::{Context, Poll},
};

use crate::keyset::KeySet;

pub struct EncryptedResponse;

impl<S: 'static, B> Transform<S, ServiceRequest> for EncryptedResponse
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<BodyLogger<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = EncryptedResponseMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(EncryptedResponseMiddleware { service }))
    }
}

pub struct EncryptedResponseMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for EncryptedResponseMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    B: MessageBody,
{
    type Response = ServiceResponse<BodyLogger<B>>;
    type Error = Error;
    type Future = WrapperStream<S, B>;

    dev::forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let auth_name: String = match try_parse_header(req.headers()) {
            Ok(name) => name,
            Err(_) => "".to_string()
        };
        WrapperStream {
            fut: self.service.call(req),
            _t: PhantomData,
            name: auth_name
        }
    }
}

#[pin_project::pin_project]
pub struct WrapperStream<S, B>
where
    B: MessageBody,
    S: Service<ServiceRequest>,
{
    #[pin]
    fut: S::Future,
    _t: PhantomData<(B,)>,
    name: String
}

impl<S, B> Future for WrapperStream<S, B>
where
    B: MessageBody,
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
{
    type Output = Result<ServiceResponse<BodyLogger<B>>, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let res = futures_util::ready!(this.fut.poll(cx));
        let name = this.name.to_string();
        let keyset: KeySet = match get_keys(&name) {
            Ok(k) => k,
            Err(_) => return Poll::Ready(Err(error::ErrorUnauthorized("")))
        };

        println!("Key: {:02X?}", (&keyset).get_derived_key().as_ref());
        let cipher = XChaCha20Poly1305::new((&keyset).get_derived_key().as_ref().into());

        Poll::Ready(res.map(|mut res| {
            res.headers_mut().append(
                HeaderName::from_static("magicant-nonce"),
                HeaderValue::from_bytes(
                    BASE64_STANDARD.encode((&keyset).get_nonce()).as_ref()
                ).unwrap_or(HeaderValue::from_static(""))
            );

            res.map_body(move |_, body| BodyLogger {
                body,
                name: name,
                enc_cipher: cipher,
                nonce: XNonce::from((&keyset).get_nonce())
            })
        }))
    }
}

#[pin_project::pin_project(PinnedDrop)]
pub struct BodyLogger<B> {
    #[pin]
    body: B,
    name: String,
    enc_cipher: XChaCha20Poly1305,
    nonce: XNonce
}

#[pin_project::pinned_drop]
impl<'a, B> PinnedDrop for BodyLogger<B> {
    // Called when Pin is dropped (Done streaming body)
    fn drop(self: Pin<&mut Self>) {
        println!("Nonce: {:02X?}", self.nonce);
        println!("response body end\nName: {:?}", self.name);
    }
}

impl<B: MessageBody> MessageBody for BodyLogger<B> {
    type Error = B::Error;

    fn size(&self) -> BodySize {
        BodySize::Stream // Only Stream encrypted response
    }

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Bytes, Self::Error>>> {
        let this = self.project();
        match this.body.poll_next(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                let chunk_slice: &[u8] = &chunk;

                // Structure of encrypted ciphertext file
                // +-------------------+--------+-------------------+--------+-----+
                // | 1st c_text len    | c_text | 2nd c_text len    | c_text | ... |
                // +-------------------+--------+-------------------+--------+-----+
                // |    u_int32        |        |    u_int32        |
                // +----+----+----+----+        +----+----+----+----+
                match this.enc_cipher.encrypt(this.nonce, chunk_slice) {
                    Ok(ciphertext) => {
                        let mut framed = BytesMut::new();
                        let u32len = ciphertext.len() as u32;
                        println!("Chunk Size: {u32len}");
                        let len = u32len.to_be_bytes();
                        framed.extend_from_slice(&len);
                        framed.extend_from_slice(&ciphertext);
                        Poll::Ready(Some(Ok(framed.freeze())))
                    }
                    Err(e) => {
                        println!("Encryption error: {:?}", e);
                        Poll::Ready(None)
                    }
                }
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

fn get_keys(name: &str) -> Result<KeySet, i32> {
    //let priv_key_path = Path::new("./.magicant/key");
    println!("Name: {name}");
    
    let priv_key_pathbuf = Path::new(env!("key_path")).join(env!("key_name"));
    let priv_key_path = priv_key_pathbuf.as_path();
    let req_pub_key_pathbuf = if let Some(path_buf) = parse_path_unrestricted(
        "./.magicant".to_string(),
        Some(format!("{}.pub", name))
    ) {
        path_buf
    } else {
        println!("path_buf 401");
        return Err(401)
    };
    let req_pub_key_path = req_pub_key_pathbuf.as_path();

    if !priv_key_path.exists() {
        // ERROR SOMETHING
        println!("priv_key 401");
        return Err(401)
    }

    if !req_pub_key_path.exists() {
        println!("pub_buf 401");
        return Err(401)
    }

    // Encryption of large files uses a 19-byte nonce
    // 4 bytes are for block counting, and 1-byte denotes the final block
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);

    Ok(KeySet::create(
        bytes_from_file(priv_key_path),
        bytes_from_file(req_pub_key_path),
        nonce
    ))
}

fn try_parse_header(header: &HeaderMap) -> Result<String, i32> {
    let auth_header = if let Some(header_auth) = header.get("Authorization") {
        header_auth
    }
    else {
        println!("header_auth 401");
        return Err(401);
    };

    let auth_vector: Vec<&str> = auth_header.to_str().unwrap()
        .split_whitespace()
        .collect();
    
    if auth_vector.len() != 2 || auth_vector[0] != "Basic" {
        println!("auth_vector 401");
        return Err(401);
    }
    let auth_token = match BASE64_STANDARD.decode(auth_vector[1]) {
        Ok(auth_decode) => match String::from_utf8(auth_decode) {
            Ok(auth_str) => auth_str,
            Err(_) => {
                println!("Error auth_str");
                return Err(401)
            }
        },
        Err(_) => {
            println!("Error auth_decode");
            return Err(401)
        }
    };

    return Ok(auth_token);
}

fn bytes_from_file(file_path: &Path) -> [u8; 32] {
    let mut f = match File::open(file_path) {
        Ok(file) => file,
        Err(_) => return [0u8; 32]
    };
    let mut buffer = [0u8; 32];
    match f.read_exact(&mut buffer) {
        Ok(_) => buffer,
        Err(_) => [0u8; 32]
    }
}

pub fn parse_path_unrestricted(path_arg: String, file_arg: Option<String>) -> Option<PathBuf> {
    let path_req: String = if let Some(file) = file_arg {
            format!("{}/{}", path_arg, file)
        } else {
            format!("{}/", path_arg)
        };
    if path_req.contains("/../") {
        return None;
    }
    Some(Path::new(&path_req).to_path_buf())
}