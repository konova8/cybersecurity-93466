# Overview
## Programma
- Introduction to Cybersecurity
- Cryptography
- Passwords and authentication
- Systems security
- Internet security
- Wireless security
- Privacy: anonymous communication, data privacy
- Web security?

## Introduction
### What is Cybersecurity?
- Tecnology/Mesure/Practice
- To prevent or mitigate the impact
- Cyberattacks

Cyberattacks: Intentional effort to steal, expose, alter, disable or destroy data/applications

### CyberAttacks
- Pishing and Social-Engineering-Based attacks
- Internet-facing service risks
- Password-related account compromises
- Misuse of information
- Network-related and man-in-the-middle attacks
- Supply chain attacks
- (Distibuted) Denial of Service attack
- Ransomware

### Definitions
- Vulnerability: A weakness that can be exploited to cause damage
- Attack: A method of exploiting a vulnerability
- Threat: A motivated, capable adversary that mounts an attack
- Zero-day vulnerability: A vulnerability that is unknown to those who should be interested in mitigating it
- Window of Opportunity: Time from when a software exploit first becomes active to the time when a patch is released by the affected vendor and applied to the affected system
- Zero-day attack: an attack that occurs during the window of opportunity

## Introduction to Cybersecurity

### Definitios
- Cryptography: Science of using math to **obscure** the meaning of the message
- Cryptoanalysis: Science of breaking encryption
- Cryptology: Cryptography + Cryptoanalysis

- Steganography: “covered writing”, hides the **existence** of a message
- Cryptography: “hidden writing”, hide the **meaning** of a message

Objective: Ensure secure communication over insecure medium

Goals:
    - Privacy (secrecy, confidentiality)
    - Authenticity
    - Integrity
    - Non-repudiation

Protocols that Enable parties to **communicate securely** and Achieve goals to **protect message confidentiality and integrity**

> Kerckhoff‘s principle: The security of a protocol should rely only on the secrecy of the keys, while protocol designs should be made public (1883)

### Attacker threat model
Two types of attacks:
- Passive: Only observes and decrypt messages
- Active: Observes, modifies, injects, or deletes messages

- Interaction with the encryption algorithm
    - Ciphertext-only attack: attacker only sees encrypted messages
    - Chosen-plaintext attack (**CPA**): Attacker may choose a number of messages and obtain the ciphertexts for them
    - Chosen-ciphertext attack (**CCA**): Attacker may choose a number of ciphertexts and obtain the plaintexts
    - Both CPA and CCA attacks may be adaptive: Choices may change based on results of previous requests

### Symmetric Encryption
- Same key for encryption and decryption
- Can use:
    - Single use keys: One key for every message
    - Multiple use keys: One key for multiple messages

### Asymmetric Encryption
Use public key for encryption and private key for decryption

### What can Cryptofraphy do
- Message Encryption
- Digital Signature
- Anonymous communication
- Anonymous digital cash

### History of Crypto
#### Symmetric Ciphers
Esempio: Cifrario di Cesare

The key space is really small, 26 possible keys, may be broken with brute force attack

#### *Mono*alphabetic substitution Ciphers
Table with how to substitute each letter of the alphabet

The space key is $26! \approx 2^88$, but may be broken with frequency analysis, with single letters or pairs (or more) of letters

#### Vigenère Cipher (16th century)
It's basically a *Poly*alphabetic substitution cipher

![vigenere-cipher](assets/vigenere-cipher.png)

- Collection of Shift Ciphers
- One letter in the ciphertext corresponds to multiple letters in the plaintext
- Frequency analysis more difficult

We can break it with:
- Guess the length of the key $l$ using some methods
- Divide the ciphertext into $l$ shift cipher encryptions
- Use frequency analysis on each shift cipher

#### Rotor Machines
We can have a longer key by having multiple rounds of substitutions

- Hebern machine with single rotor
- Enigma with 3-5 rotor

## Stream Ciphers
### One Time Pad
First example of "secure" cipher

The key is used only once, it's random and it has a uniform distribution over the key space

The problem is that the key must be as long as the plaintext (we'll see thing in binary)

For encryption we use the XOR binary operator with `m` and `k`, so we get `c`

### PseudoRandom Generators (PRGs)
We can make OTP practical by generating a PRG, that map a shorter key to a longer key, with the length equal to the message length, this is called **Stream Cipher**

This doesn't have perfect secrecy, because the key is shorter than the message (what count is the original key, not the one pseudorandom generated)

So the security depend how good is a specific PRG

### Possible Attacks
> TL;DR: Never use a key more than once, there is enough redundancy in English and ASCII encoding that from `m1 XOR m2 -> m1, m2`

For network traffic negotiate a new key for every session (as in TLS), one for client -> server, one for server -> client

#### Real world examples
##### 802.11b WEP
We send the **Initialization Vector** (IV) and the ciphertext, obtained by doing:

$$(m + CheckSum(m) \oplus PRG(IV + k), \quad \text{with + as concatenation operator}$$

The IV has length of 24 bits, the key has length of 104, this means that the keys for each frame are very related, so this is not secure!

##### Disk Encryption
Re encrypt only modified blocks

#### No Integrity (OTP is malleable)
The attacker can read and modify the ciphertext, in particular:
- Can alter the message by adding random stuff
- Can add `XOR p` to the original message
- Can invert a True or False response (if this is sent by a single bit)
- Can change part of the message (Alice -> Maria)

### Rivest Cipher 4 (RC4)
- It start by initializalizing the array `S`, that will be used for extracting pseudo random numbers
- This is done by shuffling "randomly" (we use a seed) an array from 0 to 255
- After that we can extract any time we want a pseudo random generated number, but we also swap two elements of the array `S`

The problems with this ciphter are:
- The seed must be equal for Alice and Bob
- The setup algorithm is not perfect
- Even if the setup algorithm was perfect, the output of RC4 is biased

### Modern stream ciphers (eStream)
They use a nonce along the key (seed) in the PRG, and the pair (key, nonce) is never used more than once

Example: Salsa 20 (SW + HW), 10 round of function $h$, which is invertible and designed to be fast on x86

## When a PRG is "secure"?
> It needs to be **unpredictable**

$$\forall i, \text{ there is no "efficient" way to predict bit } (i+1) \text{ for not negligible } \epsilon \\ \Rightarrow G: K \rightarrow {0, 1}^n \text{is predictable}$$
