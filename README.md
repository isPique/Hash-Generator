# Supported Hashing Algorithms

- Argon2
- BCrypt
- SCrypt
- MD5
- SHA-256
- SHA-512
- Blake2b
- PBKDF2-HMAC
- SHAKE-128
- SHAKE-256

1. **Argon2:**
   - Argon2 is a key derivation function that was selected as the winner of the Password Hashing Competition (PHC) in 2015.
   - It is designed to be memory-hard and resistant to GPU and ASIC attacks.
   - Argon2 has different configurations, including Argon2i (optimized for password hashing) and Argon2d (optimized for secure digital data).

2. **BCrypt:**
   - BCrypt is a password hashing function designed to be slow and computationally expensive.
   - It uses the Blowfish cipher in a modified key setup to hash passwords securely.
   - BCrypt automatically handles the generation of a random salt for each password.

3. **SCrypt:**
   - SCrypt is a key derivation function designed to be memory-hard and resistant to both CPU and GPU attacks.
   - It is often used for password-based key derivation, making it suitable for secure password hashing.

4. **MD5 (Message Digest Algorithm 5):**
   - MD5 is a widely used hash function that produces a 128-bit hash value.
   - It is considered cryptographically broken and unsuitable for further use in security-sensitive applications due to vulnerabilities, including collision attacks.

5. **SHA-256 (Secure Hash Algorithm 256-bit):**
   - SHA-256 is part of the SHA-2 family of cryptographic hash functions.
   - It produces a 256-bit (32-byte) hash value and is commonly used for various security applications and protocols.

6. **SHA-512 (Secure Hash Algorithm 512-bit):**
   - SHA-512 is also part of the SHA-2 family and produces a 512-bit (64-byte) hash value.
   - It provides a higher level of security and is often used in scenarios where stronger cryptographic properties are required.

7. **Blake2b:**
   - Blake2b is a cryptographic hash function that is faster than MD5, SHA-1, SHA-2, and SHA-3, while still providing high security.
   - It is suitable for a wide range of applications, including hash-based message authentication codes (HMAC).

8. **PBKDF2-HMAC (Password-Based Key Derivation Function 2 with Hash-based Message Authentication Code):**
   - PBKDF2 is a key derivation function that applies a pseudo-random function, such as HMAC, to the input password along with a salt.
   - It is commonly used to strengthen passwords before storage by making them computationally expensive to attack.

9. **SHAKE-128 and SHAKE-256:**
   - SHAKE (Secure Hash Algorithm and KEccak) is a family of hash functions designed to provide variable output length.
   - SHAKE-128 produces variable-length output with a security level of 128 bits.
   - SHAKE-256 produces variable-length output with a security level of 256 bits.

These algorithms serve different purposes, and their selection depends on factors such as security requirements, performance, and specific use cases.

# Advanced Techniques In The Context Of Password Hashing and Security Measures Beyond Simple Brute-Force Attacks or Basic Hashing

1. **Salting:** Adding a random value (salt) to each password before hashing. This ensures that even if two users have the same password, their hashed values will be different, making precomputed attacks (rainbow table attacks) less effective.

2. **Key Strengthening:** Techniques like key derivation functions (KDFs) or adaptive hash functions add computational cost to the hashing process, making it slower and more resilient against brute-force attacks. Popular choices include bcrypt, scrypt, and Argon2.

3. **Peppering:** Similar to salting, peppering involves adding a secret, global value to passwords before hashing. Unlike salts, peppers are not stored in the database, making them harder for an attacker to obtain.

4. **Multi-Factor Authentication (MFA):** Adding an additional layer of security by requiring users to provide multiple forms of identification (e.g., password plus a temporary code sent to their mobile device) makes unauthorized access more challenging.

5. **Rate Limiting and Lockout Policies:** Implementing measures to limit the number of login attempts within a specific time period or temporarily locking out accounts after multiple failed attempts helps mitigate brute-force attacks.

In summary, advanced techniques encompasses a range of security practices designed to enhance the protection of user passwords and the overall security of a system. The specific measures adopted depend on the security requirements and the potential risks associated with the application or system in question.
