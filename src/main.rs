use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, AeadCore};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Write};
use std::process::Command;
use std::thread;
use std::time::Duration;

// Function to clear the terminal screen
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

// Pauses, displays a message, then clears the terminal
fn pause_and_clear(message: &str) {
    clear_screen();
    println!("{}", message);
    thread::sleep(Duration::from_secs(3));
    clear_screen();
}

// Struct to manage encryption and decryption operations
struct EncryptionManager {
    cipher: Aes256Gcm,
    storage: HashMap<String, (Vec<u8>, Vec<u8>)>, // Maps IDs to (Nonce, Ciphertext)
}

impl EncryptionManager {
    fn new(key: &[u8]) -> Self {
        let cipher = Aes256Gcm::new_from_slice(key).expect("Failed to create cipher.");
        EncryptionManager {
            cipher,
            storage: HashMap::new(),
        }
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> (String, Vec<u8>) {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng).to_vec();
        let ciphertext = self
            .cipher
            .encrypt(&aes_gcm::Nonce::from_slice(&nonce), plaintext)
            .expect("Encryption failed!");

        let id = format!("enc-{}", self.storage.len() + 1);
        self.storage.insert(id.clone(), (nonce.clone(), ciphertext.clone()));

        // Combine nonce and ciphertext for file storage
        let mut combined = nonce.clone();
        combined.extend(ciphertext);
        (id, combined)
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

// Utility function to read content from a file
fn read_file(file_path: &str) -> Vec<u8> {
    let mut file = File::open(file_path).expect("Failed to open the file.");
    let mut content = Vec::new();
    file.read_to_end(&mut content).expect("Failed to read the file.");
    content
}

// Utility function to write content to a file
fn write_file(file_path: &str, data: &[u8]) {
    let mut file = File::create(file_path).expect("Failed to create the file.");
    file.write_all(data).expect("Failed to write to the file.");
}

fn main() {
    clear_screen(); // Clear terminal at the start of the program
    let key = Aes256Gcm::generate_key(&mut OsRng);
    let mut manager = EncryptionManager::new(&key);

    println!("Welcome to File Encryption/Decryption Program!");
    println!("Encryption Key (hex): {:x?}", key);

    loop {
        clear_screen(); // Clear before displaying menu
        println!("Choose an option:");
        println!("1. Encrypt");
        println!("2. Decrypt a file");
        println!("3. View Stored IDs");
        println!("4. Exit");

        let mut choice = String::new();
        io::stdin()
            .read_line(&mut choice)
            .expect("Failed to read input.");
        let choice = choice.trim();
        clear_screen(); // Clear after user input

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
                clear_screen(); // Clear after user input

                match encrypt_choice {
                    "1" => {
                        // Encrypt user input and save to UserEncryption.txt
                        println!("Enter text to encrypt:");
                        let mut user_input = String::new();
                        io::stdin()
                            .read_line(&mut user_input)
                            .expect("Failed to read input.");
                        let user_input = user_input.trim();

                        let (id, combined) = manager.encrypt(user_input.as_bytes());
                        write_file("UserEncryption.txt", &combined);
                        pause_and_clear(&format!(
                            "Your input has been encrypted and stored with ID: '{}' in 'UserEncryption.txt'.",
                            id
                        ));
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
                        let (id, combined) = manager.encrypt(&plaintext);
                        write_file("Encrypt.txt", &combined);
                        pause_and_clear(&format!(
                            "File has been encrypted and stored with ID: '{}' in 'Encrypt.txt'.",
                            id
                        ));
                    }
                    _ => pause_and_clear("Invalid option. Returning to the main menu."),
                }
            }
            "2" => {
                println!("Enter the ID to decrypt:");
                let mut id = String::new();
                io::stdin()
                    .read_line(&mut id)
                    .expect("Failed to read input.");
                let id = id.trim();
                clear_screen(); // Clear after user input

                if let Some(decrypted) = manager.decrypt(id) {
                    write_file("Decrypt.txt", &decrypted);
                    pause_and_clear("Decryption successful. Output saved to 'Decrypt.txt'.");
                } else {
                    pause_and_clear("Invalid ID. Decryption failed.");
                }
            }
            "3" => {
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
