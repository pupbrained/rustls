use chacha20poly1305::{AeadInPlace, KeyInit, KeySizeUser};
use rustls::crypto::cipher;
use rustls::internal::msgs::{base::Payload, codec::Codec}; // FIXME
use rustls::{ContentType, PeerMisbehaved, ProtocolVersion};

pub struct Chacha20Poly1305;

impl cipher::Tls13AeadAlgorithm for Chacha20Poly1305 {
    fn key_len(&self) -> usize {
        chacha20poly1305::ChaCha20Poly1305::key_size()
    }

    fn encrypter(&self, key: cipher::AeadKey, iv: cipher::Iv) -> Box<dyn cipher::MessageEncrypter> {
        Box::new(Cipher(
            chacha20poly1305::ChaCha20Poly1305::new_from_slice(key.as_ref()).unwrap(),
            iv,
        ))
    }

    fn decrypter(&self, key: cipher::AeadKey, iv: cipher::Iv) -> Box<dyn cipher::MessageDecrypter> {
        Box::new(Cipher(
            chacha20poly1305::ChaCha20Poly1305::new_from_slice(key.as_ref()).unwrap(),
            iv,
        ))
    }
}

struct Cipher(chacha20poly1305::ChaCha20Poly1305, cipher::Iv);

impl cipher::MessageEncrypter for Cipher {
    fn encrypt(
        &self,
        m: cipher::BorrowedPlainMessage,
        seq: u64,
    ) -> Result<cipher::OpaqueMessage, rustls::Error> {
        let total_len = m.payload.len() + 1 + 16;
        let mut payload = Vec::with_capacity(total_len);
        payload.extend_from_slice(m.payload);
        m.typ.encode(&mut payload);

        let nonce = chacha20poly1305::Nonce::from(cipher::make_nonce(&self.1, seq));
        let aad = [0x17, 0x3, 0x3, (total_len >> 8) as u8, total_len as u8];

        self.0
            .encrypt_in_place(&nonce, &aad, &mut payload)
            .map_err(|_| rustls::Error::EncryptError)
            .and_then(|_| {
                Ok(cipher::OpaqueMessage {
                    typ: ContentType::ApplicationData,
                    version: ProtocolVersion::TLSv1_2,
                    payload: Payload::new(payload),
                })
            })
    }
}

fn unpad_tls13(v: &mut Vec<u8>) -> ContentType {
    loop {
        match v.pop() {
            Some(0) => {}
            Some(content_type) => return ContentType::from(content_type),
            None => return ContentType::Unknown(0),
        }
    }
}

impl cipher::MessageDecrypter for Cipher {
    fn decrypt(
        &self,
        mut m: cipher::OpaqueMessage,
        seq: u64,
    ) -> Result<cipher::PlainMessage, rustls::Error> {
        let payload = &mut m.payload.0;
        let nonce = chacha20poly1305::Nonce::from(cipher::make_nonce(&self.1, seq));
        let aad = [
            0x17,
            0x3,
            0x3,
            (payload.len() >> 8) as u8,
            payload.len() as u8,
        ];

        self.0
            .decrypt_in_place(&nonce, &aad, payload)
            .map_err(|_| rustls::Error::DecryptError)?;

        // FIXME: deduplicate this
        if payload.len() > 16384 + 1 {
            return Err(rustls::Error::PeerSentOversizedRecord);
        }

        m.typ = unpad_tls13(payload);
        if m.typ == ContentType::Unknown(0) {
            return Err(PeerMisbehaved::IllegalTlsInnerPlaintext.into());
        }

        if payload.len() > 16384 {
            return Err(rustls::Error::PeerSentOversizedRecord);
        }

        m.version = ProtocolVersion::TLSv1_3;
        // FIXME: ///
        Ok(m.into_plain_message())
    }
}
