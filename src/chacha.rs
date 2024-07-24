use std::io::Read;

use chacha20poly1305::aead::{generic_array::typenum::Unsigned, AeadCore, AeadMutInPlace, OsRng};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};

type NonceSize = <ChaCha20Poly1305 as AeadCore>::NonceSize;

enum ChaChaEncryptorPhase {
	Nonce,
	Ciphertext,
	Complete,
}

pub struct ChaChaEncryptor {
	cipher: ChaCha20Poly1305,
	nonce: Nonce,
	input_stream: Box<dyn std::io::Read>,
	phase: ChaChaEncryptorPhase,
}

impl ChaChaEncryptor {
	pub fn new(cipher: ChaCha20Poly1305, input_stream: Box<dyn std::io::Read>) -> Self {
		let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
		let phase = ChaChaEncryptorPhase::Nonce;
		Self {
			cipher,
			nonce,
			input_stream,
			phase,
		}
	}
}

impl Iterator for ChaChaEncryptor {
	type Item = Vec<u8>;

	// TODO: Bit pointless for this to be an iterator, but it would be useful if we can get the
	// stream design working.
	fn next(&mut self) -> Option<Self::Item> {
		match self.phase {
			ChaChaEncryptorPhase::Nonce => {
				let nonce_buffer = self.nonce.as_slice();
				self.phase = ChaChaEncryptorPhase::Ciphertext;
				Some(nonce_buffer.to_vec())
			}
			ChaChaEncryptorPhase::Ciphertext => {
				let mut buffer = Vec::new();
				self.input_stream.read_to_end(&mut buffer).expect("failed to read plaintext");
				self.cipher
					.encrypt_in_place(&self.nonce, &[], &mut buffer)
					.expect("failed to encrypt buffer");
				self.phase = ChaChaEncryptorPhase::Complete;
				Some(buffer)
			}
			ChaChaEncryptorPhase::Complete => None,
		}
	}
}

enum ChaChaDecryptorPhase {
	Plaintext,
	Complete,
}

pub struct ChaChaDecryptor {
	cipher: ChaCha20Poly1305,
	input_stream: Box<dyn std::io::Read>,
	phase: ChaChaDecryptorPhase,
}

impl ChaChaDecryptor {
	pub fn new(cipher: ChaCha20Poly1305, input_stream: Box<dyn std::io::Read>) -> Self {
		let phase = ChaChaDecryptorPhase::Plaintext;
		Self {
			cipher,
			input_stream,
			phase,
		}
	}
}

impl Iterator for ChaChaDecryptor {
	type Item = Vec<u8>;

	// TODO: Also switch to streaming. AtomicBool would work to read the nonce only on the first
	// iteration.
	fn next(&mut self) -> Option<Self::Item> {
		match self.phase {
			ChaChaDecryptorPhase::Plaintext => {
				// Read the nonce and save it.
				let nonce_buffer = &mut [0u8; NonceSize::USIZE];
				self.input_stream.read_exact(nonce_buffer).unwrap_or_else(|_| {
					panic!("failed to read nonce of size {} bytes", NonceSize::USIZE)
				});
				let nonce = *Nonce::from_slice(nonce_buffer);

				// Read the rest of the cyper text and decrypt it.
				let mut buffer = Vec::new();
				self.input_stream.read_to_end(&mut buffer).expect("failed to read cyphertext");
				self.cipher
					.decrypt_in_place(&nonce, &[], &mut buffer)
					.expect("failed to decrypt buffer");
				self.phase = ChaChaDecryptorPhase::Complete;
				Some(buffer)
			}
			ChaChaDecryptorPhase::Complete => None,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use chacha20poly1305::KeyInit;
	use rand::{distributions::Alphanumeric, Rng};

	#[test]
	fn test_encrypt_decrypt() {
		let key = ChaCha20Poly1305::generate_key(&mut OsRng);
		let cipher = ChaCha20Poly1305::new(&key);

		let input: String = rand::thread_rng()
			.sample_iter(&Alphanumeric)
			.take(1024 * 1024 + 42)
			.map(char::from)
			.collect();
		let encrypter = ChaChaEncryptor::new(
			cipher.clone(),
			Box::new(std::io::Cursor::new(input.clone())),
		);
		let ciphertext: Vec<u8> = encrypter.flatten().collect();
		let decrypter = ChaChaDecryptor::new(cipher, Box::new(std::io::Cursor::new(ciphertext)));
		let plaintext: Vec<u8> = decrypter.flatten().collect();
		assert!(input.as_bytes() == plaintext.as_slice());
	}
}
