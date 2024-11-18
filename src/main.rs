use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, AeadCore};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Write};
use std::process::Command;
use std::thread;
use std::time::Duration;

fn clear_screen() {
    if cfg!(target_os = "windows") {
        Command::new("cmd")
            .args(&["/C", "cls"])
            .status()
            .expect("Failed to clear screen.");
    } else {
        Command::new("clear")
            .status()
            .expect("Failed to clear screen.");
    }
}

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
                .decrypt(&aes_gcm::Nonce::from_slice(nonce), ciphertext.as_slice())
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

fn pause_and_clear(msg: &str) {
    clear_screen();
    println!("{}", msg);
    thread::sleep(Duration::from_secs(3));
    clear_screen();
}

fn main() {
    let key = Aes256Gcm::generate_key(&mut OsRng);
    let mut manager = EncryptionManager::new(&key);

    println!("Welcome to File Encryption/Decryption Program!");
    println!("Encryption Key (hex): {:x?}", key);

    loop {
        clear_screen();
        println!("Choose an option:");
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
                clear_screen();
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
                        println!("Enter text to encrypt:");
                        let mut user_input = String::new();
                        io::stdin()
                            .read_line(&mut user_input)
                            .expect("Failed to read input.");
                        let user_input = user_input.trim();

                        let id = manager.encrypt(user_input.as_bytes());
                        pause_and_clear(&format!(
                            "Text encrypted and stored with ID: '{}'",
                            id
                        ));
                    }
                    "2" => {
                        println!("Enter the file path to encrypt:");
                        let mut file_path = String::new();
                        io::stdin()
                            .read_line(&mut file_path)
                            .expect("Failed to read input.");
                        let file_path = file_path.trim();

                        let plaintext = read_file(file_path);
                        let id = manager.encrypt(&plaintext);
                        pause_and_clear(&format!(
                            "File encrypted and stored with ID: '{}'.",
                            id
                        ));
                    }
                    _ => {
                        pause_and_clear("Invalid option. Returning to the main menu.");
                    }
                }
            }
            "2" => {
                clear_screen();
                println!("Enter the ID to decrypt:");
                let mut id = String::new();
                io::stdin()
                    .read_line(&mut id)
                    .expect("Failed to read input.");
                let id = id.trim();

                if let Some(decrypted) = manager.decrypt(id) {
                    let output_path = "Decrypt.txt";
                    write_file(output_path, &decrypted);
                    pause_and_clear(&format!(
                        "Decryption successful. Output saved to '{}'.",
                        output_path
                    ));
                } else {
                    pause_and_clear("Invalid ID. Decryption failed.");
                }
            }
            "3" => {
                clear_screen();
                let mut ids = String::from("Stored IDs:\n");
                for id in manager.storage.keys() {
                    ids.push_str(&format!("- {}\n", id));
                }
                pause_and_clear(&ids);
            }
            "4" => {
                pause_and_clear("Exiting program. Goodbye!");
                break;
            }
            _ => {
                pause_and_clear("Invalid choice. Please try again.");
            }
        }
    }
}
