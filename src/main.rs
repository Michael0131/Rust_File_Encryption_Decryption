// Importing necessary modules for encryption and file operations
use aes_gcm::aead::{Aead, KeyInit, OsRng}; // AES-GCM encryption library with random generator
use aes_gcm::{Aes256Gcm, AeadCore}; // Specific encryption cipher: AES-256 GCM
use std::collections::HashMap; // HashMap to store encrypted data with IDs
use std::fs::File; // File handling for reading and writing
use std::io::{self, Read, Write}; // Standard I/O for user input and file operations
use std::process::Command; // Command for clearing the terminal
use std::thread; // Thread for delays
use std::time::Duration; // Duration for pause timing

// Function to clear the terminal screen
fn clear_screen() {
    if cfg!(target_os = "windows") {
        // Clear screen on Windows systems
        Command::new("cmd")
            .args(&["/C", "cls"])
            .status()
            .expect("Failed to clear screen.");
    } else {
        // Clear screen on non-Windows systems
        Command::new("clear")
            .status()
            .expect("Failed to clear screen.");
    }
}

// Pauses, displays a message, then clears the terminal
fn pause_and_clear(message: &str) {
    clear_screen(); // Clear the screen before displaying the message
    println!("{}", message); // Show the message
    thread::sleep(Duration::from_secs(3)); // Pause for 3 seconds
    clear_screen(); // Clear the screen after the pause
}

// Struct to manage encryption and decryption operations
struct EncryptionManager {
    cipher: Aes256Gcm, // Cipher used for encryption and decryption
    storage: HashMap<String, (Vec<u8>, Vec<u8>)>, // Maps IDs to (Nonce, Ciphertext)
}

// Implementation of EncryptionManager
impl EncryptionManager {
    // Creates a new EncryptionManager with the provided encryption key
    fn new(key: &[u8]) -> Self {
        let cipher = Aes256Gcm::new_from_slice(key).expect("Failed to create cipher."); // Initialize cipher
        EncryptionManager {
            cipher,
            storage: HashMap::new(), // Initialize empty HashMap for storage
        }
    }

    // Encrypts plaintext and stores it with an ID
    fn encrypt(&mut self, plaintext: &[u8]) -> (String, Vec<u8>) {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng).to_vec(); // Generate random nonce
        let ciphertext = self
            .cipher
            .encrypt(&aes_gcm::Nonce::from_slice(&nonce), plaintext) // Perform encryption
            .expect("Encryption failed!");

        let id = format!("enc-{}", self.storage.len() + 1); // Generate unique ID for storage
        self.storage.insert(id.clone(), (nonce.clone(), ciphertext.clone())); // Store nonce and ciphertext

        let mut combined = nonce.clone(); // Combine nonce and ciphertext for file storage
        combined.extend(ciphertext);
        (id, combined) // Return ID and combined data
    }

    // Decrypts stored data using its ID
    fn decrypt(&self, id: &str) -> Option<Vec<u8>> {
        if let Some((nonce, ciphertext)) = self.storage.get(id) {
            // Retrieve nonce and ciphertext by ID
            self.cipher
                .decrypt(&aes_gcm::Nonce::from_slice(nonce), ciphertext.as_slice()) // Perform decryption
                .ok() // Return decrypted data if successful
        } else {
            None // Return None if ID is invalid
        }
    }
}

// Utility function to read content from a file
fn read_file(file_path: &str) -> Vec<u8> {
    let mut file = File::open(file_path).expect("Failed to open the file."); // Open the file
    let mut content = Vec::new();
    file.read_to_end(&mut content).expect("Failed to read the file."); // Read file content
    content // Return file content as a Vec<u8>
}

// Utility function to write content to a file
fn write_file(file_path: &str, data: &[u8]) {
    let mut file = File::create(file_path).expect("Failed to create the file."); // Create or overwrite the file
    file.write_all(data).expect("Failed to write to the file."); // Write data to the file
}

// Main function for user interaction and program flow
fn main() {
    clear_screen(); // Clear terminal at the start of the program
    let key = Aes256Gcm::generate_key(&mut OsRng); // Generate encryption key
    let mut manager = EncryptionManager::new(&key); // Create a new encryption manager

    println!("Welcome to File Encryption/Decryption Program!");
    println!("Encryption Key (hex): {:x?}", key); // Display the encryption key

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
            .expect("Failed to read input."); // Read user's choice
        let choice = choice.trim();
        clear_screen(); // Clear after user input

        match choice {
            "1" => {
                clear_screen();
                println!("Choose an encryption option:");
                println!("1. Encrypt user input");
                println!("2. Encrypt a file");

                let mut encrypt_choice = String::new();
                io::stdin()
                    .read_line(&mut encrypt_choice)
                    .expect("Failed to read input."); // Read encryption choice
                let encrypt_choice = encrypt_choice.trim();
                clear_screen(); // Clear after user input

                match encrypt_choice {
                    "1" => {
                        clear_screen();
                        // Encrypt user input and save to UserEncryption.txt
                        println!("Enter text to encrypt:");
                        let mut user_input = String::new();
                        io::stdin()
                            .read_line(&mut user_input)
                            .expect("Failed to read input."); // Read user input
                        let user_input = user_input.trim();

                        let (id, combined) = manager.encrypt(user_input.as_bytes()); // Encrypt input
                        write_file("UserEncryption.txt", &combined); // Save encrypted data
                        pause_and_clear(&format!(
                            "Your input has been encrypted and stored with ID: '{}' in 'UserEncryption.txt'.",
                            id
                        ));
                    }
                    "2" => {
                        clear_screen();
                        // Encrypt file and save to Encrypt.txt
                        println!("Enter the file path to encrypt:");
                        let mut file_path = String::new();
                        io::stdin()
                            .read_line(&mut file_path)
                            .expect("Failed to read input."); // Read file path
                        let file_path = file_path.trim();

                        let plaintext = read_file(file_path); // Read file content
                        let (id, combined) = manager.encrypt(&plaintext); // Encrypt file content
                        write_file("Encrypt.txt", &combined); // Save encrypted data
                        pause_and_clear(&format!(
                            "File has been encrypted and stored with ID: '{}' in 'Encrypt.txt'.",
                            id
                        ));
                    }
                    _ => pause_and_clear("Invalid option. Returning to the main menu."), // Handle invalid choice
                }
            }
            "2" => {
                clear_screen();
                println!("Enter the ID to decrypt:");
                let mut id = String::new();
                io::stdin()
                    .read_line(&mut id)
                    .expect("Failed to read input."); // Read ID for decryption
                let id = id.trim();
                clear_screen(); // Clear after user input

                if let Some(decrypted) = manager.decrypt(id) {
                    write_file("Decrypt.txt", &decrypted); // Save decrypted data
                    pause_and_clear("Decryption successful. Output saved to 'Decrypt.txt'.");
                } else {
                    pause_and_clear("Invalid ID. Decryption failed."); // Handle invalid ID
                }
            }
            "3" => {
                clear_screen();
                let mut ids = String::from("Stored IDs:\n");
                for id in manager.storage.keys() {
                    ids.push_str(&format!("- {}\n", id)); // List all stored IDs
                }
                pause_and_clear(&ids);
            }
            "4" => {
                clear_screen();
                pause_and_clear("Exiting program. Goodbye!");
                break; // Exit the program
            }
            _ => {
                pause_and_clear("Invalid choice. Please try again."); // Handle invalid menu choice
            }
        }
    }
}
