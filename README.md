# testRSA

This project implements the basics of the RSA encryption algorithm (public-key cryptography), and illustrates how two parties—Alice and Bob—can securely communicate while an attacker attempts to intercept their messages.

## Scenario: Alice, Bob, and the Attacker

- **Alice** wants to send a confidential message to **Bob**.
- **Bob** generates a public and private key pair and shares the public key with Alice.
- **Alice** encrypts her message using Bob’s public key and sends it.
- **An Attacker** may intercept the encrypted message, but without the private key, cannot decrypt it.
- **Bob** uses his private key to decrypt Alice’s message.

---

## How RSA Works (Simplified)

1. **Key Generation (Bob):**
    - Bob selects two large prime numbers (_p_ and _q_).
    - Computes _n = p × q_ and _phi(n) = (p-1) × (q-1)_.
    - Chooses an encryption exponent _e_ (relatively prime to _phi(n)_).
    - Computes the decryption exponent _d_ (modular inverse of _e_ modulo _phi(n)_).
    - Public key: (_e_, _n_); Private key: (_d_, _n_).

2. **Encryption (Alice):**
    - Converts the message to an integer (_m_).
    - Calculates the ciphertext: _c = m^e mod n_.
    - Sends the ciphertext _c_ to Bob.

3. **Decryption (Bob):**
    - Receives _c_, uses his private key to compute: _m = c^d mod n_.
    - Converts _m_ back to the original message.

4. **Attacker:**
    - The attacker may see _c_ and the public key, but cannot feasibly deduce _d_ (the private key) to decrypt the message due to the mathematical hardness of factoring large integers.

---

## How to Use This Project

### 1. Clone the Repository

```sh
git clone https://github.com/AnyaMeetoo492/testRSA.git
cd testRSA
```

### 2. Key Generation

Bob generates his public and private keys by running the relevant script/module.

### 3. Encrypt Message

Alice uses the provided script/module to encrypt her message with Bob's public key.

### 4. Send & Receive

Alice sends the encrypted message (ciphertext) to Bob. Even if an attacker intercepts it, they cannot read the message.

### 5. Decrypt Message

Bob decrypts the received ciphertext using his private key and retrieves the original message.

---

## Example Usage

```python
# Generate keys
public_key, private_key = generate_keys()

# Alice encrypts
ciphertext = encrypt(public_key, "Hello Bob!")

# Bob decrypts
message = decrypt(private_key, ciphertext)

print(message)  # "Hello Bob!"
```

*(Replace function names above with actual function names from your implementation)*

---

## Disclaimer

This implementation is for **educational purposes only**. Do not use it in production or for any sensitive data, as real-world cryptography requires extra care.
