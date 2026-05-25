# E-voting Simulation
Implementation of a secure voting system in which votes are encrypted using homomorphic encryption, and the election results are calculated without revealing individual votes.  

**Properties**
- Eligibility is proven by certificate
- Each voter gets a private receipt only they can use to verify their vote
- Double-voting is blocked
- Fake certificates are blocked
- Individual votes are never decrypted  

## Steps:
1. Build the Certificate Authority (CA)  
    - RSA keypair geneartion  
    - CA will sign documents ("certificates") that prove a person is allowed to vote  
2. Build the Election Authority  
    - Paillier keypair generation  
3. Register voters  
    - Every voter gets their own RSA keypair  
    - Every voter gets a CA  
4. Generate random votes  
    - System never sees these cleartext values  
    - Encrypts the vote with Paillier using public key  
    - Saves a receipt: keeps the vote and the random value r used during encryption, so the voter can later prove what they sent  
    - Signs the vote with their own RSA key  
5. Submit votes  
    - Checks if the certificate is signed by trusted CA  
    - Checks if the ballot is signed by the person named in the certificate  
    - Checks if the voter already voted (reject double votes)  
6. Attack #1: someone tries to vote twice  
7. Attack #2: someone tries to vote with a fake certificate  
8. Every voter checks their own vote  
    - Each voter decrypts with their saved randomness  
9. Count votes without decrypting  
    - Multiplies all the ciphertexts together (Paillier homomorphic property)  
    - Decrypts a single number the count of 'Yes' votes  
