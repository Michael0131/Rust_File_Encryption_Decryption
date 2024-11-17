use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, AeadCore};
use std::fs::{File};
use std::io::{self, Read, Write};

/// Encrypt plaintext and return ciphertext with the nonce.
///
/// # Arguments
/// - `plaintext`: Data to encrypt.
/// - `cipher`: The initialized AES-GCM cipher.
fn encrypt(plaintext: &[u8], cipher: &Aes256Gcm) -> (Vec<u8>, Vec<u8>) {
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng).to_vec();
    let ciphertext = cipher
        .encrypt(&aes_gcm::Nonce::from_slice(&nonce), plaintext)
        .expect("Encryption failed!");
    (nonce, ciphertext)
}

/// Decrypt ciphertext using nonce and return plaintext.
///
/// # Arguments
/// - `ciphertext`: Data to decrypt.
/// - `nonce`: Nonce used during encryption.
/// - `cipher`: The initialized AES-GCM cipher.
fn decrypt(ciphertext: &[u8], nonce: &[u8], cipher: &Aes256Gcm) -> Vec<u8> {
    cipher
        .decrypt(&aes_gcm::Nonce::from_slice(nonce), ciphertext)
        .expect("Decryption failed!")
}

/// Read the entire contents of a file.
fn read_file(file_path: &str) -> Vec<u8> {
    let mut file = File::open(file_path).expect("Failed to open the file.");
    let mut content = Vec::new();
    file.read_to_end(&mut content).expect("Failed to read the file.");
    content
}

/// Write data to a file.
fn write_file(file_path: &str, data: &[u8]) {
    let mut file = File::create(file_path).expect("Failed to create the file.");
    file.write_all(data).expect("Failed to write to the file.");
}

fn main() {
    // Generate a random 32-byte encryption key
    let key = Aes256Gcm::generate_key(&mut OsRng);
    let cipher = Aes256Gcm::new(&key);

    println!("Welcome to File Encryption/Decryption Program!");
    println!("Encryption Key (hex): {:x?}", key);

    loop {
        println!("\nChoose an option:");
        println!("1. Encrypt user input");
        println!("2. Encrypt a file");
        println!("3. Decrypt a file");
        println!("4. Exit");

        let mut choice = String::new();
        io::stdin()
            .read_line(&mut choice)
            .expect("Failed to read input.");
        let choice = choice.trim();

        match choice {
            "1" => {
                // Encrypt user input
                println!("Enter text to encrypt:");
                let mut user_input = String::new();
                io::stdin()
                    .read_line(&mut user_input)
                    .expect("Failed to read input.");
                let user_input = user_input.trim();

                let (nonce, ciphertext) = encrypt(user_input.as_bytes(), &cipher);
                println!("Encrypted data (hex): {:x?}", ciphertext);
                println!("Nonce (hex): {:x?}", nonce);

                let decrypted = decrypt(&ciphertext, &nonce, &cipher);
                println!("Decrypted text: {}", String::from_utf8(decrypted).unwrap());
            }
            "2" => {
                // Encrypt file contents
                println!("Enter the file path to encrypt:");
                let mut file_path = String::new();
                io::stdin()
                    .read_line(&mut file_path)
                    .expect("Failed to read input.");
                let file_path = file_path.trim();

                println!("Enter the output file path for the encrypted data:");
                let mut output_path = String::new();
                io::stdin()
                    .read_line(&mut output_path)
                    .expect("Failed to read input.");
                let output_path = output_path.trim();

                let plaintext = read_file(file_path);
                let (nonce, ciphertext) = encrypt(&plaintext, &cipher);

                // Combine nonce and ciphertext for output
                let mut combined = nonce.clone();
                combined.extend(ciphertext);
                write_file(output_path, &combined);

                println!("File encrypted successfully!");
            }
            "3" => {
                // Decrypt file contents
                println!("Enter the encrypted file path:");
                let mut file_path = String::new();
                io::stdin()
                    .read_line(&mut file_path)
                    .expect("Failed to read input.");
                let file_path = file_path.trim();

                println!("Enter the output file path for the decrypted data:");
                let mut output_path = String::new();
                io::stdin()
                    .read_line(&mut output_path)
                    .expect("Failed to read input.");
                let output_path = output_path.trim();

                let encrypted_data = read_file(file_path);

                // Split nonce and ciphertext
                let (nonce, ciphertext) = encrypted_data.split_at(12);
                let decrypted = decrypt(ciphertext, nonce, &cipher);
                write_file(output_path, &decrypted);

                println!("File decrypted successfully!");
            }
            "4" => {
                println!("Exiting program. Goodbye!");
                break;
            }
            _ => {
                println!("Invalid choice. Please try again.");
            }
        }
    }
}
