use blake3;
use x25519_dalek::{PublicKey, StaticSecret};

#[allow(dead_code)]
pub struct KeySet {
    priv_key: [u8; 32],
    pub_key: [u8; 32],
    nonce: [u8; 24],
    derived_key: [u8; 32]
}

#[allow(dead_code)]
impl KeySet {
    pub fn create(priv_key: [u8; 32], pub_key: [u8; 32], nonce: [u8; 24]) -> Self {
        KeySet {
            priv_key: priv_key,
            pub_key: pub_key,
            nonce: nonce,
            derived_key: KeySet::derive_secret(
                &StaticSecret::from(priv_key),
                &PublicKey::from(pub_key),
                &nonce
            )
        }
    }

    pub fn update(&mut self, nonce: [u8; 24]) {
        self.nonce = nonce;
        self.derived_key = KeySet::derive_secret(
            &StaticSecret::from(self.priv_key),
            &PublicKey::from(self.pub_key),
            &self.nonce
        )
    }

    pub fn get_derived_key(&self) -> [u8; 32] {
        self.derived_key
    }

    pub fn get_nonce(&self) -> [u8; 24] {
        println!("{:02X?}", self.nonce);
        self.nonce
    }

    pub fn get_reduced_nonce(&self) -> [u8; 19] {
        self.nonce[0..19].try_into().unwrap()
    }

    fn derive_secret(
        private_key: &StaticSecret,
        public_key: &PublicKey,
        nonce: &[u8; 24]
    ) -> [u8; 32] {
        let dif_hel_secret = private_key.diffie_hellman(&public_key);
    
        let mut kdf = blake3::Hasher::new_keyed(dif_hel_secret.as_bytes());
        kdf.update(nonce);
        let shared_key = kdf.finalize();

        //println!("Diffie-Hellman: {:02X?}", dif_hel_secret.as_bytes());
        //println!("Derived Key: {:02X?}", shared_key.as_bytes());
        //println!("Nonce: {:02X?}", nonce);
    
        return *shared_key.as_bytes();
    }
}