use actix_http::{h1, header::HeaderMap};
use actix_web::{
    dev::{self, Service, ServiceRequest, ServiceResponse, Transform},
    error, web, Error
};
use base64::prelude::*;
use chacha20poly1305::{
    //aead::{stream, Aead},
    aead::Aead,
    KeyInit, XChaCha20Poly1305
};
use futures_util::future::LocalBoxFuture;
use rand::rngs::OsRng;
use std::{
    fs::{self, File},
    future::{ready, Ready},
    io::{Read, Write},
    path::{Path, PathBuf},
    rc::Rc,
};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::keyset::KeySet;

pub struct E2E;

struct EncHeader {
    auth_token: String,
    nonce: [u8; 24]
}

impl<S: 'static, B> Transform<S, ServiceRequest> for E2E
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = E2EMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(E2EMiddleware {
            service: Rc::new(service),
        }))
    }
}

pub struct E2EMiddleware<S> {
    // This is special: We need this to avoid lifetime issues.
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for E2EMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    dev::forward_ready!(service);

    fn call(&self, mut req: ServiceRequest) -> Self::Future {
        let svc = self.service.clone();

        Box::pin(async move {
            // extract bytes from request
            let body = req.extract::<web::Bytes>().await.unwrap();
            let headers = req.headers();
            let header_map = match verify_header(headers) {
                Ok(h) => h,
                Err(e) => {
                    // Call svc chain so logger can log request
                    let _res = svc.call(req).await?;

                    return match e {
                        403 => Err(error::ErrorForbidden("")),
                        401 => Err(error::ErrorUnauthorized("")),
                        _ => Err(error::ErrorBadRequest(""))
                    };
                }
            };
            
            println!("request body (middleware): {body:?}");
            println!("request headers: {:?}", headers);

            // Check for Existing Keys and Create them if they don't exist
            // Obtains KeySet containing derived_secret
            let keyset = match verify_keys(&header_map) {
                Ok(k) => k,
                Err(e) => {
                    // Call svc chain so logger can log request
                    let _res = svc.call(req).await?;

                    return match e {
                        500 => Err(error::ErrorInternalServerError("")),
                        401 => Err(error::ErrorUnauthorized("")),
                        _ => Err(error::ErrorBadRequest(""))
                    };
                }
            };

            // Decrpyt Request Body
            let decoded_body = match BASE64_STANDARD.decode(body) {
                Ok(auth_decode) => auth_decode,
                Err(_) => return Err(error::ErrorBadRequest(""))
            };
            let decrypted_body = match decrypt_body(&decoded_body, &keyset) {
                Ok(b) => b,
                Err(_) => return Err(error::ErrorBadRequest(""))
            };
            //return Err(error::ErrorInternalServerError(""));

            // re-insert body back into request to be used by handlers
            req.set_payload(bytes_to_payload(decrypted_body.into()));

            let res = svc.call(req).await?;
            
            // Check if secrets exist

            // Encrypt Response Body if OK 200
            let status = res.response().status().as_u16();
            if status == 200 {
                let cache_path = Path::new("./cache/");
                if !cache_path.exists() && fs::create_dir(cache_path).is_err(){
                    return Err(error::ErrorInternalServerError(""));
                }
            }

            println!("response: {:?}", res.headers());
            Ok(res)
        })
    }
}

fn bytes_to_payload(buf: web::Bytes) -> dev::Payload {
    let (_, mut pl) = h1::Payload::create(true);
    pl.unread_data(buf);
    dev::Payload::from(pl)
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

fn verify_header(header: &HeaderMap) -> Result<EncHeader, i32> {
    let nonce: [u8; 24] = if let Some(header_nonce) = header.get("magicant-nonce") {
        // Forces size of slice to match size of nonce
        match header_nonce.as_bytes().try_into() {
            Ok(n) => n,
            Err(_) => return Err(401)
        }
    }
    else {
        return Err(403);
    };
    let auth_header = if let Some(header_auth) = header.get("Authorization") {
        header_auth
    }
    else {
        return Err(401);
    };

    let auth_vector: Vec<&str> = auth_header.to_str().unwrap()
        .split_whitespace()
        .collect();
    
    if auth_vector.len() != 2 || auth_vector[0] != "Basic" {
        return Err(401);
    }
    let auth_token = match BASE64_STANDARD.decode(auth_vector[1]) {
        Ok(auth_decode) => match String::from_utf8(auth_decode) {
            Ok(auth_str) => auth_str,
            Err(_) => return Err(401)
        },
        Err(_) => return Err(401)
    };

    Ok(EncHeader {
        auth_token: auth_token,
        nonce: nonce
    })
}

fn verify_keys(header_map: &EncHeader) -> Result<KeySet, i32> {
    if fs::create_dir_all("./.magicant").is_err() {
        return Err(500);
    }
    let rand_generator = OsRng {};
    let priv_key_path = Path::new("./.magicant/key");
    let pub_key_path = Path::new("./.magicant/key.pub");
    let req_pub_key_pathbuf = if let Some(path_buf) = parse_path_unrestricted(
        "./.magicant".to_string(),
        Some(format!("{}.pub", header_map.auth_token))
    ) {
        path_buf
    } else {
        return Err(401)
    };
    let req_pub_key_path = req_pub_key_pathbuf.as_path();

    if !priv_key_path.exists() || !pub_key_path.exists() {
        let priv_key = StaticSecret::random_from_rng(rand_generator);
        let pub_key = PublicKey::from(&priv_key);

        // Write private key
        let mut f_priv_key = match File::create(priv_key_path) {
            Ok(f) => f,
            Err(_) => return Err(500)
        };
        if f_priv_key.write_all(&priv_key.to_bytes()).is_err() {
            return Err(500);
        }
        
        // Write public key
        let mut f_pub_key = match File::create(pub_key_path) {
            Ok(f) => f,
            Err(_) => return Err(500)
        };
        if f_pub_key.write_all(&pub_key.to_bytes()).is_err() {
            return Err(500);
        }
    }

    if !req_pub_key_path.exists() {
        return Err(401)
    }

    Ok(KeySet::create(
        bytes_from_file(priv_key_path),
        bytes_from_file(req_pub_key_path),
        header_map.nonce
    ))
}

fn parse_path_unrestricted(path_arg: String, file_arg: Option<String>) -> Option<PathBuf> {
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

fn decrypt_body(
    body: &[u8],
    keyset: &KeySet
) -> Result<Vec<u8>, i32> {
    let aead = XChaCha20Poly1305::new(keyset.get_derived_key().as_ref().into());
    /*let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, keyset.get_nonce().as_ref().into());

    const BUFFER_LEN: usize = 516;
    let mut buf = [0u8; BUFFER_LEN];*/

    let nonce: &[u8; 24] = &keyset.get_nonce();

    let decrypted_body = match aead.decrypt(nonce.into(), body) {
        Ok(b) => b,
        Err(e) => {
            println!("{:?}", e);
            return Err(400)
        }
    };

    match fs::write("./output.bin", decrypted_body.clone()) {
        Ok(_) => Ok(decrypted_body),
        Err(_) => Err(500)
    }
}

#[allow(dead_code)]
fn encrypt_body(
    body: &[u8],
    keyset: &KeySet
) -> Result<(), i32> {
    let cipher = XChaCha20Poly1305::new(keyset.get_derived_key().as_ref().into());

    let nonce: &[u8; 24] = &keyset.get_nonce();
    //let mut enc_cipher = stream::EncryptorBE32::from_aead(cipher.clone(), nonce.as_ref().into());

    let encrypted_body = match cipher.encrypt(nonce.into(), body) {
        Ok(b) => b,
        Err(e) => {
            println!("{:?}", e);
            return Err(400)
        }
    };

    match fs::write("./input.bin", encrypted_body) {
        Ok(_) => Ok(()),
        Err(_) => Err(500)
    }
}