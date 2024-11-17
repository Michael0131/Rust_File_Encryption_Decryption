use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, AeadCore};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Write};

struct EncryptionManager {
    cipher: Aes256Gcm,
    storage: HashMap<String, (Vec<u8>, Vec<u8>)>, // ID -> (Nonce, Ciphertext)
}

impl EncryptionManager {
    fn new(key: &[u8]) -> Self {
        let cipher = Aes256Gcm::new_from_slice(key).expect("Failed to create cipher.");
        EncryptionManager {
            cipher,
            storage: HashMap::new(),
        }
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> String {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng).to_vec();
        let ciphertext = self
            .cipher
            .encrypt(&aes_gcm::Nonce::from_slice(&nonce), plaintext)
            .expect("Encryption failed!");

        let id = format!("enc-{}", self.storage.len() + 1);
        self.storage.insert(id.clone(), (nonce, ciphertext));
        id
    }

    fn decrypt(&self, id: &str) -> Option<Vec<u8>> {
        if let Some((nonce, ciphertext)) = self.storage.get(id) {
            self.cipher
                .decrypt(&aes_gcm::Nonce::from_slice(nonce), ciphertext)
                .ok()
        } else {
            None
        }
    }
}

fn read_file(file_path: &str) -> Vec<u8> {
    let mut file = File::open(file_path).expect("Failed to open the file.");
    let mut content = Vec::new();
    file.read_to_end(&mut content).expect("Failed to read the file.");
    content
}

fn write_file(file_path: &str, data: &[u8]) {
    let mut file = File::create(file_path).expect("Failed to create the file.");
    file.write_all(data).expect("Failed to write to the file.");
}

fn main() {
    let key = Aes256Gcm::generate_key(&mut OsRng);
    let mut manager = EncryptionManager::new(&key);

    println!("Welcome to File Encryption/Decryption Program!");
    println!("Encryption Key (hex): {:x?}", key);

    loop {
        println!("\nChoose an option:");
        println!("1. Encrypt");
        println!("2. Decrypt");
        println!("3. View Stored IDs");
        println!("4. Exit");

        let mut choice = String::new();
        io::stdin()
            .read_line(&mut choice)
            .expect("Failed to read input.");
        let choice = choice.trim();

        match choice {
            "1" => {
                println!("Choose an encryption option:");
                println!("1. Encrypt user input");
                println!("2. Encrypt a file");

                let mut encrypt_choice = String::new();
                io::stdin()
                    .read_line(&mut encrypt_choice)
                    .expect("Failed to read input.");
                let encrypt_choice = encrypt_choice.trim();

                match encrypt_choice {
                    "1" => {
                        // Encrypt user input and save to UserEncryption.txt
                        println!("Enter text to encrypt:");
                        let mut user_input = String::new();
                        io::stdin()
                            .read_line(&mut user_input)
                            .expect("Failed to read input.");
                        let user_input = user_input.trim();

                        let (nonce, ciphertext) = manager.encrypt(user_input.as_bytes());
                        let mut combined = nonce.clone();
                        combined.extend(ciphertext);

                        write_file("UserEncryption.txt", &combined);
                        println!("User input encrypted and saved to 'UserEncryption.txt'.");
                    }
                    "2" => {
                        // Encrypt file and save to Encrypt.txt
                        println!("Enter the file path to encrypt:");
                        let mut file_path = String::new();
                        io::stdin()
                            .read_line(&mut file_path)
                            .expect("Failed to read input.");
                        let file_path = file_path.trim();

                        let plaintext = read_file(file_path);
                        let id = manager.encrypt(&plaintext);
                        println!("File encrypted and stored with ID: '{}'.", id);
                    }
                    _ => println!("Invalid option. Returning to the main menu."),
                }
            }
            "2" => {
                println!("Choose a decryption option:");
                println!("1. Decrypt UserEncryption.txt");
                println!("2. Decrypt Encrypt.txt");
                println!("3. Decrypt using an ID");

                let mut decrypt_choice = String::new();
                io::stdin()
                    .read_line(&mut decrypt_choice)
                    .expect("Failed to read input.");
                let decrypt_choice = decrypt_choice.trim();

                match decrypt_choice {
                    "1" => {
                        // Decrypt UserEncryption.txt
                        let encrypted_data = read_file("UserEncryption.txt");
                        let (nonce, ciphertext) = encrypted_data.split_at(12);
                        if let Ok(decrypted) = manager
                            .cipher
                            .decrypt(&aes_gcm::Nonce::from_slice(nonce), ciphertext)
                        {
                            write_file("Decrypt.txt", &decrypted);
                            println!(
                                "Decrypted UserEncryption.txt saved to 'Decrypt.txt'."
                            );
                        } else {
                            println!("Decryption failed for UserEncryption.txt.");
                        }
                    }
                    "2" => {
                        // Decrypt Encrypt.txt
                        let encrypted_data = read_file("Encrypt.txt");
                        let (nonce, ciphertext) = encrypted_data.split_at(12);
                        if let Ok(decrypted) = manager
                            .cipher
                            .decrypt(&aes_gcm::Nonce::from_slice(nonce), ciphertext)
                        {
                            write_file("Decrypt.txt", &decrypted);
                            println!("Decrypted Encrypt.txt saved to 'Decrypt.txt'.");
                        } else {
                            println!("Decryption failed for Encrypt.txt.");
                        }
                    }
                    "3" => {
                        // Decrypt using an ID from HashMap
                        println!("Enter the ID to decrypt:");
                        let mut id = String::new();
                        io::stdin()
                            .read_line(&mut id)
                            .expect("Failed to read input.");
                        let id = id.trim();

                        if let Some(decrypted) = manager.decrypt(id) {
                            write_file("Decrypt.txt", &decrypted);
                            println!(
                                "Decryption successful. Output saved to 'Decrypt.txt'."
                            );
                        } else {
                            println!("Invalid ID. Decryption failed.");
                        }
                    }
                    _ => println!("Invalid option. Returning to the main menu."),
                }
            }
            "3" => {
                println!("Stored IDs:");
                for id in manager.storage.keys() {
                    println!("- {}", id);
                }
            }
            "4" => {
                println!("Exiting program. Goodbye!");
                break;
            }
            _ => println!("Invalid choice. Please try again."),
        }
    }
}
