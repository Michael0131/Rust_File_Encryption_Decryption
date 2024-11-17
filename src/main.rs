use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, AeadCore};
use std::fs::File;
use std::io::{self, Read, Write};

fn encrypt(plaintext: &[u8], cipher: &Aes256Gcm) -> (Vec<u8>, Vec<u8>) {
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng).to_vec();
    let ciphertext = cipher
        .encrypt(&aes_gcm::Nonce::from_slice(&nonce), plaintext)
        .expect("Encryption failed!");
    (nonce, ciphertext)
}

fn decrypt(ciphertext: &[u8], nonce: &[u8], cipher: &Aes256Gcm) -> Vec<u8> {
    cipher
        .decrypt(&aes_gcm::Nonce::from_slice(nonce), ciphertext)
        .expect("Decryption failed!")
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
    let cipher = Aes256Gcm::new(&key);

    println!("Welcome to File Encryption/Decryption Program!");
    println!("Encryption Key (hex): {:x?}", key);

    loop {
        println!("\nChoose an option:");
        println!("1. Encrypt");
        println!("2. Decrypt a file");
        println!("3. Exit");

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

                        let (nonce, ciphertext) = encrypt(user_input.as_bytes(), &cipher);

                        let mut combined = nonce.clone();
                        combined.extend(ciphertext);
                        let output_path = "UserEncryption.txt";
                        write_file(output_path, &combined);

                        println!(
                            "Your input has been encrypted and saved to '{}'.",
                            output_path
                        );
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
                        let (nonce, ciphertext) = encrypt(&plaintext, &cipher);

                        let mut combined = nonce.clone();
                        combined.extend(ciphertext);
                        let output_path = "Encrypt.txt";
                        write_file(output_path, &combined);

                        println!("File has been encrypted and saved to '{}'.", output_path);
                    }
                    _ => println!("Invalid option. Returning to the main menu."),
                }
            }
            "2" => {
                // Decrypt a file
                println!("Choose a decryption file:");
                println!("1. Decrypt UserEncryption.txt");
                println!("2. Decrypt Encrypt.txt");

                let mut decrypt_choice = String::new();
                io::stdin()
                    .read_line(&mut decrypt_choice)
                    .expect("Failed to read input.");
                let decrypt_choice = decrypt_choice.trim();

                let file_path = match decrypt_choice {
                    "1" => "UserEncryption.txt",
                    "2" => "Encrypt.txt",
                    _ => {
                        println!("Invalid option. Returning to the main menu.");
                        continue;
                    }
                };

                let encrypted_data = read_file(file_path);

                let (nonce, ciphertext) = encrypted_data.split_at(12);
                let decrypted = decrypt(ciphertext, nonce, &cipher);

                let output_path = "Decrypt.txt";
                write_file(output_path, &decrypted);

                println!(
                    "The file '{}' has been decrypted and saved to '{}'.",
                    file_path, output_path
                );
            }
            "3" => {
                println!("Exiting program. Goodbye!");
                break;
            }
            _ => {
                println!("Invalid choice. Please try again.");
            }
        }
    }
}
