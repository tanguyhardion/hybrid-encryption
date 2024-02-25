# hybrid-encryption

This repository contains the code for the hybrid encryption of a file using RSA and AES algorithms. The code is written in Java (17).

## Classes

The repository contains the following classes:

- `ExchangeTest` : class containing the main method, generating the RSA key pairs and initializing the threads.
- `Alex` : class generating the AES secret key and sending it to Bob. Then, this class sends a message to Bob, encrypted with the AES secret key and expects a reply. 
- `Bob` : class receiving the AES secret key and Alex's message. Then, Bob sends a reply to Alex, encrypted with the AES secret key.
- `Encryption` : helper class containing the methods for the encryption and decryption of the specified data with the Cipher provided.

`Alex` and `Bob` are two different threads, simulating two different users.
