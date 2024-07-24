// Copyright 2024 Dominic Zippilli
// Author: github.com/domZippilli

use std::{io::Write, path::PathBuf};

use chacha20poly1305::{aead::OsRng, ChaCha20Poly1305, Key, KeyInit};
use clap::{Parser, Subcommand};

use chacha_cli::chacha::{ChaChaDecryptor, ChaChaEncryptor};

const BUFFER_SIZE: usize = 1024 * 1024; // 1 MiB

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
	/// Subcommand to run
	#[command(subcommand)]
	command: Commands,
}

#[derive(Subcommand)]
enum Commands {
	/// Encrypt plaintext from stdin, emitting ciphertext to stdout
	Encrypt {
		/// Path to key file
		#[arg(value_name = "FILE")]
		keypath: PathBuf,
	},
	/// Decrypt ciphertext from stdin, emitting plaintext to stdout
	Decrypt {
		/// Path to key file
		#[arg(value_name = "FILE")]
		keypath: PathBuf,
	},
	/// Generate a new key and write it to stdout
	KeyGen {},
}

fn main() {
	let cli = Cli::parse();
	match &cli.command {
		Commands::Encrypt { keypath } => {
			eprintln!("Encrypting with key: {}", keypath.display());
			let key_bytes = std::fs::read(keypath).expect("couldn't read key file");
			let cipher = build_cipher(key_bytes.as_slice());
			write_iter_bytes(
				ChaChaEncryptor::new(cipher, Box::new(std::io::stdin())),
				&mut std::io::stdout().lock(),
			);
		}
		Commands::Decrypt { keypath } => {
			eprintln!("Decrypting with key: {}", keypath.display());
			let key_bytes = std::fs::read(keypath).expect("couldn't read key file");
			let cipher = build_cipher(key_bytes.as_slice());
			write_iter_bytes(
				ChaChaDecryptor::new(cipher, Box::new(std::io::stdin())),
				&mut std::io::stdout().lock(),
			);
		}
		Commands::KeyGen {} => {
			eprintln!("Generating key...");
			let key = ChaCha20Poly1305::generate_key(&mut OsRng);
			write_iter_bytes(
				key.chunks(BUFFER_SIZE).map(|x| x.to_vec()),
				&mut std::io::stdout().lock(),
			);
		}
	}
}

/// Build a ChaCha20Poly1305 cipher from a key file.
fn build_cipher(key_bytes: &[u8]) -> ChaCha20Poly1305 {
	let key = Key::from_slice(key_bytes);
	ChaCha20Poly1305::new(key)
}

/// Write an iterator of byte buffers to a writer.
///
/// The writer is flushed after all bytes are written.
fn write_iter_bytes(bytes_iter: impl Iterator<Item = Vec<u8>>, writer: &mut impl Write) {
	for bytes in bytes_iter {
		writer.write_all(&bytes).expect("couldn't write to stdout");
	}
	writer.flush().expect("couldn't flush stdout");
}

#[cfg(test)]
mod tests {
	use std::io::Cursor;

	use super::*;

	use chacha20poly1305::KeyInit;

	#[test]
	fn test_workflow() {
		// Generate a key and write the bytes to storage.
		let key = ChaCha20Poly1305::generate_key(&mut OsRng);
		let mut key_bytes: Vec<u8> = Vec::new();
		write_iter_bytes(key.chunks(BUFFER_SIZE).map(|x| x.to_vec()), &mut key_bytes);

		// Build a cipher from the key bytes.
		let cipher = build_cipher(key_bytes.as_slice());

		// Encrypt some plaintext and write the ciphertext to storage.
		let original_plaintext = Box::new("hello".as_bytes());
		let mut ciphertext: Vec<u8> = Vec::new();
		write_iter_bytes(
			ChaChaEncryptor::new(cipher.clone(), original_plaintext.clone()),
			&mut ciphertext,
		);

		// Decrypt the ciphertext and write the plaintext to storage.
		let mut decrypted_plaintext: Vec<u8> = Vec::new();
		write_iter_bytes(
			ChaChaDecryptor::new(cipher, Box::new(Cursor::new(ciphertext))),
			&mut decrypted_plaintext,
		);
		assert_eq!(original_plaintext.to_vec(), decrypted_plaintext);
	}
}
