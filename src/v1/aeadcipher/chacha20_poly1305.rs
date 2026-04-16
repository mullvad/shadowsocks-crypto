use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(feature = "faster-crypto")] {
        use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};

        pub struct ChaCha20Poly1305(LessSafeKey);

        impl ChaCha20Poly1305 {
            pub fn new(key: &[u8]) -> ChaCha20Poly1305 {
                let unbound = UnboundKey::new(&CHACHA20_POLY1305, key).expect("CHACHA20_POLY1305 key");
                ChaCha20Poly1305(LessSafeKey::new(unbound))
            }

            pub fn key_size() -> usize {
                CHACHA20_POLY1305.key_len()
            }

            pub fn nonce_size() -> usize {
                CHACHA20_POLY1305.nonce_len()
            }

            pub fn tag_size() -> usize {
                CHACHA20_POLY1305.tag_len()
            }

            pub fn encrypt(&self, nonce: &[u8], plaintext_in_ciphertext_out: &mut [u8]) {
                let nonce = Nonce::try_assume_unique_for_key(nonce).expect("CHACHA20_POLY1305 nonce");
                let (plaintext, out_tag) =
                    plaintext_in_ciphertext_out.split_at_mut(plaintext_in_ciphertext_out.len() - Self::tag_size());
                let tag = self
                    .0
                    .seal_in_place_separate_tag(nonce, Aad::empty(), plaintext)
                    .expect("CHACHA20_POLY1305 encrypt");
                out_tag.copy_from_slice(tag.as_ref());
            }

            pub fn decrypt(&self, nonce: &[u8], ciphertext_in_plaintext_out: &mut [u8]) -> bool {
                let nonce = Nonce::try_assume_unique_for_key(nonce).expect("CHACHA20_POLY1305 nonce");
                self.0.open_in_place(nonce, Aad::empty(), ciphertext_in_plaintext_out).is_ok()
            }
        }
    } else {
        use chacha20poly1305::ChaCha20Poly1305 as CryptoChaCha20Poly1305;
        use chacha20poly1305::{
            aead::{generic_array::typenum::Unsigned, AeadCore, AeadInPlace, KeySizeUser, KeyInit},
            Key,
            Nonce,
            Tag,
        };

        pub struct ChaCha20Poly1305(CryptoChaCha20Poly1305);

        impl ChaCha20Poly1305 {
            pub fn new(key: &[u8]) -> ChaCha20Poly1305 {
                let key = Key::from_slice(key);
                ChaCha20Poly1305(CryptoChaCha20Poly1305::new(key))
            }

            pub fn key_size() -> usize {
                <CryptoChaCha20Poly1305 as KeySizeUser>::KeySize::to_usize()
            }

            pub fn nonce_size() -> usize {
                <CryptoChaCha20Poly1305 as AeadCore>::NonceSize::to_usize()
            }

            pub fn tag_size() -> usize {
                <CryptoChaCha20Poly1305 as AeadCore>::TagSize::to_usize()
            }

            pub fn encrypt(&self, nonce: &[u8], plaintext_in_ciphertext_out: &mut [u8]) {
                let nonce = Nonce::from_slice(nonce);
                let (plaintext, out_tag) =
                    plaintext_in_ciphertext_out.split_at_mut(plaintext_in_ciphertext_out.len() - Self::tag_size());
                let tag = self
                    .0
                    .encrypt_in_place_detached(nonce, &[], plaintext)
                    .expect("CHACHA20_POLY1305 encrypt");
                out_tag.copy_from_slice(tag.as_slice())
            }

            pub fn decrypt(&self, nonce: &[u8], ciphertext_in_plaintext_out: &mut [u8]) -> bool {
                let nonce = Nonce::from_slice(nonce);
                let (ciphertext, in_tag) =
                    ciphertext_in_plaintext_out.split_at_mut(ciphertext_in_plaintext_out.len() - Self::tag_size());
                let in_tag = Tag::from_slice(in_tag);
                self.0.decrypt_in_place_detached(nonce, &[], ciphertext, in_tag).is_ok()
            }
        }
    }
}
