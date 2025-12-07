"""
Manual RSA Digital Signature Implementation
-------------------------------------------
Implements RSA key generation, signing, and verification
WITHOUT using any external cryptography library.

Components:
1. Prime number generation (Miller-Rabin primality test)
2. RSA key pair generation
3. SHA-256 hash function (manual implementation)
4. RSA signature creation and verification
"""

import random
import json
import base64

# ========================================
# SHA-256 MANUAL IMPLEMENTATION
# ========================================

# SHA-256 constants (first 32 bits of fractional parts of cube roots of first 64 primes)
SHA256_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

# Initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
SHA256_H = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

def right_rotate(value, amount):
    """Right rotate a 32-bit integer"""
    return ((value >> amount) | (value << (32 - amount))) & 0xFFFFFFFF

def sha256_manual(message):
    """
    Manual SHA-256 implementation
    
    Args:
        message: bytes or string to hash
    
    Returns:
        SHA-256 hash as hex string
    """
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    # Pre-processing: adding padding bits
    original_length = len(message) * 8  # Length in bits
    message += b'\x80'  # Append bit '1' to message
    
    # Append zeros until message length ≡ 448 (mod 512)
    while (len(message) * 8) % 512 != 448:
        message += b'\x00'
    
    # Append original length as 64-bit big-endian integer
    message += original_length.to_bytes(8, byteorder='big')
    
    # Initialize hash values
    h = list(SHA256_H)
    
    # Process message in 512-bit (64-byte) chunks
    for chunk_start in range(0, len(message), 64):
        chunk = message[chunk_start:chunk_start + 64]
        
        # Create message schedule array (64 words of 32 bits each)
        w = []
        
        # First 16 words are directly from the chunk
        for i in range(16):
            w.append(int.from_bytes(chunk[i*4:(i+1)*4], byteorder='big'))
        
        # Extend to 64 words
        for i in range(16, 64):
            s0 = right_rotate(w[i-15], 7) ^ right_rotate(w[i-15], 18) ^ (w[i-15] >> 3)
            s1 = right_rotate(w[i-2], 17) ^ right_rotate(w[i-2], 19) ^ (w[i-2] >> 10)
            w.append((w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF)
        
        # Initialize working variables
        a, b, c, d, e, f, g, h_var = h
        
        # Main compression loop
        for i in range(64):
            S1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25)
            ch = (e & f) ^ ((e ^ 0xFFFFFFFF) & g)  # Use XOR with all 1s instead of ~
            temp1 = (h_var + S1 + ch + SHA256_K[i] + w[i]) & 0xFFFFFFFF
            S0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xFFFFFFFF
            
            h_var = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF
        
        # Add compressed chunk to current hash value
        h[0] = (h[0] + a) & 0xFFFFFFFF
        h[1] = (h[1] + b) & 0xFFFFFFFF
        h[2] = (h[2] + c) & 0xFFFFFFFF
        h[3] = (h[3] + d) & 0xFFFFFFFF
        h[4] = (h[4] + e) & 0xFFFFFFFF
        h[5] = (h[5] + f) & 0xFFFFFFFF
        h[6] = (h[6] + g) & 0xFFFFFFFF
        h[7] = (h[7] + h_var) & 0xFFFFFFFF
    
    # Produce final hash value (big-endian)
    return ''.join(format(x, '08x') for x in h)

def sha256_bytes(message):
    """Return SHA-256 hash as bytes"""
    hash_hex = sha256_manual(message)
    return bytes.fromhex(hash_hex)


# ========================================
# RSA MANUAL IMPLEMENTATION
# ========================================

def mod_pow(base, exponent, modulus):
    """
    Fast modular exponentiation using square-and-multiply algorithm
    Computes: (base ^ exponent) mod modulus
    """
    if modulus == 1:
        return 0
    
    result = 1
    base = base % modulus
    
    while exponent > 0:
        # If exponent is odd, multiply result with base
        if exponent & 1:
            result = (result * base) % modulus
        # Exponent must be even now
        exponent = exponent >> 1
        base = (base * base) % modulus
    
    return result

def miller_rabin_test(n, k=20):
    """
    Miller-Rabin primality test
    
    Args:
        n: Number to test
        k: Number of rounds (more rounds = more accuracy)
    
    Returns:
        True if n is probably prime, False if composite
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Witness loop
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = mod_pow(a, d, n)
        
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(r - 1):
            x = mod_pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    
    return True

def generate_prime(bits):
    """Generate a random prime number with specified bit length"""
    while True:
        # Generate random odd number
        n = random.getrandbits(bits)
        n |= (1 << bits - 1) | 1  # Set MSB and LSB
        
        if miller_rabin_test(n):
            return n

def extended_gcd(a, b):
    """Extended Euclidean Algorithm - returns (gcd, x, y) where ax + by = gcd"""
    if a == 0:
        return b, 0, 1
    
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    
    return gcd, x, y

def mod_inverse(e, phi):
    """Compute modular multiplicative inverse of e mod phi"""
    gcd, x, _ = extended_gcd(e % phi, phi)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    return (x % phi + phi) % phi

def gcd(a, b):
    """Greatest Common Divisor"""
    while b:
        a, b = b, a % b
    return a

def generate_rsa_keypair(bits=1024):
    """
    Generate RSA key pair manually
    
    Args:
        bits: Key size in bits (default 1024 for faster generation)
    
    Returns:
        Dictionary containing public and private key components
    """
    print(f"🔐 Generating {bits}-bit RSA key pair...")
    
    # Generate two distinct primes p and q
    print("   Generating prime p...")
    p = generate_prime(bits // 2)
    print("   Generating prime q...")
    q = generate_prime(bits // 2)
    
    while p == q:
        q = generate_prime(bits // 2)
    
    # Calculate modulus n = p * q
    n = p * q
    
    # Calculate Euler's totient φ(n) = (p-1)(q-1)
    phi = (p - 1) * (q - 1)
    
    # Choose public exponent e (commonly 65537)
    e = 65537
    
    # Ensure gcd(e, phi) = 1
    while gcd(e, phi) != 1:
        e += 2
    
    # Calculate private exponent d ≡ e^(-1) (mod φ(n))
    d = mod_inverse(e, phi)
    
    print("✅ RSA key pair generated successfully!")
    
    return {
        'public_key': {
            'n': n,  # Modulus
            'e': e   # Public exponent
        },
        'private_key': {
            'n': n,  # Modulus
            'd': d,  # Private exponent
            'p': p,  # Prime factor 1 (for optimization)
            'q': q   # Prime factor 2 (for optimization)
        }
    }

def int_to_bytes(n, length=None):
    """Convert integer to bytes"""
    if length is None:
        length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, byteorder='big')

def bytes_to_int(b):
    """Convert bytes to integer"""
    return int.from_bytes(b, byteorder='big')


# ========================================
# RSA SIGNATURE FUNCTIONS
# ========================================

def pkcs1_v15_pad(message_hash, key_size_bytes):
    """
    PKCS#1 v1.5 padding for signature
    
    Format: 0x00 0x01 [0xFF padding] 0x00 [DigestInfo]
    
    DigestInfo for SHA-256:
    SEQUENCE {
        SEQUENCE { OID sha256, NULL }
        OCTET STRING hash
    }
    """
    # SHA-256 DigestInfo prefix (DER encoded)
    sha256_digest_info = bytes([
        0x30, 0x31,  # SEQUENCE, length 49
        0x30, 0x0d,  # SEQUENCE, length 13
        0x06, 0x09,  # OID, length 9
        0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,  # SHA-256 OID
        0x05, 0x00,  # NULL
        0x04, 0x20   # OCTET STRING, length 32
    ])
    
    # Convert hash to bytes if it's hex string
    if isinstance(message_hash, str):
        hash_bytes = bytes.fromhex(message_hash)
    else:
        hash_bytes = message_hash
    
    # DigestInfo = prefix + hash
    digest_info = sha256_digest_info + hash_bytes
    
    # Calculate padding length
    # Format: 0x00 0x01 [0xFF...] 0x00 [digest_info]
    padding_length = key_size_bytes - 3 - len(digest_info)
    
    if padding_length < 8:
        raise ValueError("Key size too small for this hash")
    
    # Build padded message
    padded = b'\x00\x01' + (b'\xff' * padding_length) + b'\x00' + digest_info
    
    return padded

def pkcs1_v15_unpad(padded_bytes):
    """
    Remove PKCS#1 v1.5 padding and extract hash
    
    Returns the hash bytes if valid, raises ValueError otherwise
    """
    if len(padded_bytes) < 11:
        raise ValueError("Invalid padding: too short")
    
    if padded_bytes[0:2] != b'\x00\x01':
        raise ValueError("Invalid padding: wrong header")
    
    # Find the 0x00 separator
    separator_index = padded_bytes.find(b'\x00', 2)
    if separator_index < 10:  # Must have at least 8 bytes of 0xFF
        raise ValueError("Invalid padding: separator not found")
    
    # Check padding bytes are all 0xFF
    for i in range(2, separator_index):
        if padded_bytes[i] != 0xFF:
            raise ValueError("Invalid padding: non-0xFF byte in padding")
    
    # Extract DigestInfo
    digest_info = padded_bytes[separator_index + 1:]
    
    # SHA-256 DigestInfo prefix
    sha256_prefix = bytes([
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09,
        0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20
    ])
    
    if not digest_info.startswith(sha256_prefix):
        raise ValueError("Invalid DigestInfo: not SHA-256")
    
    # Extract hash (last 32 bytes for SHA-256)
    hash_bytes = digest_info[len(sha256_prefix):]
    
    if len(hash_bytes) != 32:
        raise ValueError("Invalid hash length")
    
    return hash_bytes

def rsa_sign(message, private_key):
    """
    Create RSA digital signature
    
    Process:
    1. Hash message with SHA-256
    2. Apply PKCS#1 v1.5 padding
    3. Sign with private key: signature = padded^d mod n
    
    Args:
        message: String or bytes to sign
        private_key: Dictionary with 'n' and 'd'
    
    Returns:
        Base64-encoded signature
    """
    # Step 1: Hash the message
    message_hash = sha256_manual(message)
    
    # Step 2: Calculate key size in bytes
    n = private_key['n']
    d = private_key['d']
    key_size_bytes = (n.bit_length() + 7) // 8
    
    # Step 3: Apply PKCS#1 v1.5 padding
    padded = pkcs1_v15_pad(message_hash, key_size_bytes)
    
    # Step 4: Convert to integer
    padded_int = bytes_to_int(padded)
    
    # Step 5: Sign: signature = padded^d mod n
    signature_int = mod_pow(padded_int, d, n)
    
    # Step 6: Convert to bytes and encode
    signature_bytes = int_to_bytes(signature_int, key_size_bytes)
    
    return base64.b64encode(signature_bytes).decode('utf-8')

def rsa_verify(message, signature_b64, public_key):
    """
    Verify RSA digital signature
    
    Process:
    1. Decode signature
    2. Recover padded hash: padded = signature^e mod n
    3. Remove padding and extract hash
    4. Hash original message
    5. Compare hashes
    
    Args:
        message: Original message (string or bytes)
        signature_b64: Base64-encoded signature
        public_key: Dictionary with 'n' and 'e'
    
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        # Step 1: Decode signature
        signature_bytes = base64.b64decode(signature_b64)
        signature_int = bytes_to_int(signature_bytes)
        
        # Step 2: Recover padded hash
        n = public_key['n']
        e = public_key['e']
        key_size_bytes = (n.bit_length() + 7) // 8
        
        recovered_int = mod_pow(signature_int, e, n)
        recovered_bytes = int_to_bytes(recovered_int, key_size_bytes)
        
        # Step 3: Remove padding and extract hash
        extracted_hash = pkcs1_v15_unpad(recovered_bytes)
        
        # Step 4: Hash original message
        computed_hash = sha256_bytes(message)
        
        # Step 5: Compare hashes (constant-time comparison)
        if len(extracted_hash) != len(computed_hash):
            return False
        
        result = 0
        for a, b in zip(extracted_hash, computed_hash):
            result |= a ^ b
        
        return result == 0
        
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False


# ========================================
# KEY SERIALIZATION / DESERIALIZATION
# ========================================

def export_public_key(public_key):
    """Export public key as JSON string (PEM-like format)"""
    return json.dumps({
        'type': 'RSA_PUBLIC_KEY',
        'n': str(public_key['n']),  # Convert to string for JSON
        'e': public_key['e']
    })

def export_private_key(private_key):
    """Export private key as JSON string"""
    return json.dumps({
        'type': 'RSA_PRIVATE_KEY',
        'n': str(private_key['n']),
        'd': str(private_key['d']),
        'p': str(private_key['p']),
        'q': str(private_key['q'])
    })

def import_public_key(key_json):
    """Import public key from JSON string"""
    data = json.loads(key_json) if isinstance(key_json, str) else key_json
    return {
        'n': int(data['n']),
        'e': int(data['e'])
    }

def import_private_key(key_json):
    """Import private key from JSON string"""
    data = json.loads(key_json) if isinstance(key_json, str) else key_json
    return {
        'n': int(data['n']),
        'd': int(data['d']),
        'p': int(data['p']),
        'q': int(data['q'])
    }


# ========================================
# RSA ENCRYPTION/DECRYPTION (for key exchange)
# ========================================

def rsa_encrypt(plaintext, public_key):
    """
    RSA encryption with PKCS#1 v1.5 padding (for small data like DES keys)
    
    Args:
        plaintext: String to encrypt (should be small, like a key)
        public_key: Dictionary with 'n' and 'e'
    
    Returns:
        Base64-encoded ciphertext
    """
    n = public_key['n']
    e = public_key['e']
    key_size_bytes = (n.bit_length() + 7) // 8
    
    # Convert plaintext to bytes
    if isinstance(plaintext, str):
        plaintext_bytes = plaintext.encode('utf-8')
    else:
        plaintext_bytes = plaintext
    
    # PKCS#1 v1.5 encryption padding
    # Format: 0x00 0x02 [random non-zero bytes] 0x00 [plaintext]
    max_plaintext_len = key_size_bytes - 11
    if len(plaintext_bytes) > max_plaintext_len:
        raise ValueError(f"Plaintext too long: {len(plaintext_bytes)} > {max_plaintext_len}")
    
    # Generate random padding (non-zero bytes)
    padding_length = key_size_bytes - 3 - len(plaintext_bytes)
    padding = bytes([random.randint(1, 255) for _ in range(padding_length)])
    
    # Build padded message
    padded = b'\x00\x02' + padding + b'\x00' + plaintext_bytes
    
    # Convert to integer and encrypt
    padded_int = bytes_to_int(padded)
    cipher_int = mod_pow(padded_int, e, n)
    
    # Convert to bytes
    cipher_bytes = int_to_bytes(cipher_int, key_size_bytes)
    
    return base64.b64encode(cipher_bytes).decode('utf-8')

def rsa_decrypt(ciphertext_b64, private_key):
    """
    RSA decryption with PKCS#1 v1.5 padding removal
    
    Args:
        ciphertext_b64: Base64-encoded ciphertext
        private_key: Dictionary with 'n' and 'd'
    
    Returns:
        Decrypted plaintext as string
    """
    n = private_key['n']
    d = private_key['d']
    key_size_bytes = (n.bit_length() + 7) // 8
    
    # Decode ciphertext
    cipher_bytes = base64.b64decode(ciphertext_b64)
    cipher_int = bytes_to_int(cipher_bytes)
    
    # Decrypt
    padded_int = mod_pow(cipher_int, d, n)
    padded_bytes = int_to_bytes(padded_int, key_size_bytes)
    
    # Remove PKCS#1 v1.5 encryption padding
    if padded_bytes[0:2] != b'\x00\x02':
        raise ValueError("Invalid padding header")
    
    # Find the 0x00 separator
    separator_index = padded_bytes.find(b'\x00', 2)
    if separator_index < 10:
        raise ValueError("Invalid padding: separator not found")
    
    # Extract plaintext
    plaintext_bytes = padded_bytes[separator_index + 1:]
    
    return plaintext_bytes.decode('utf-8')


# ========================================
# CERTIFICATE SIGNING HELPER
# ========================================

def sign_certificate_data(cert_data, ca_private_key):
    """
    Sign certificate data with CA's private key
    
    Args:
        cert_data: Dictionary of certificate fields
        ca_private_key: CA's private key dictionary
    
    Returns:
        Base64-encoded signature
    """
    # Serialize certificate data deterministically
    data_to_sign = json.dumps(cert_data, sort_keys=True)
    
    # Sign with RSA
    return rsa_sign(data_to_sign, ca_private_key)

def verify_certificate_signature(certificate, ca_public_key):
    """
    Verify certificate signature
    
    Args:
        certificate: Certificate dictionary with 'ca_signature'
        ca_public_key: CA's public key dictionary
    
    Returns:
        True if signature is valid
    """
    # Extract signature
    signature = certificate['ca_signature']
    
    # Recreate data that was signed
    cert_data = {k: v for k, v in certificate.items() 
                 if k not in ['ca_signature', 'ca_public_key']}
    data_to_verify = json.dumps(cert_data, sort_keys=True)
    
    # Verify
    return rsa_verify(data_to_verify, signature, ca_public_key)


# ========================================
# TEST / DEMO FUNCTIONS
# ========================================

def test_sha256():
    """Test SHA-256 implementation"""
    print("\n" + "="*60)
    print("Testing SHA-256 Implementation")
    print("="*60)
    
    # Test vectors
    test_cases = [
        ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        ("hello world", "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"),
    ]
    
    for message, expected in test_cases:
        result = sha256_manual(message)
        status = "✅" if result == expected else "❌"
        print(f"{status} SHA256('{message}')")
        print(f"   Expected: {expected}")
        print(f"   Got:      {result}")

def test_rsa_signature():
    """Test RSA signature implementation"""
    print("\n" + "="*60)
    print("Testing RSA Digital Signature")
    print("="*60)
    
    # Generate keys (smaller for faster testing)
    print("\n1. Generating RSA key pair...")
    keypair = generate_rsa_keypair(bits=1024)
    
    # Test message
    message = "Hello, this is a test message for digital signature!"
    print(f"\n2. Message: '{message}'")
    
    # Sign
    print("\n3. Signing message...")
    signature = rsa_sign(message, keypair['private_key'])
    print(f"   Signature (first 50 chars): {signature[:50]}...")
    
    # Verify with correct message
    print("\n4. Verifying signature...")
    is_valid = rsa_verify(message, signature, keypair['public_key'])
    print(f"   ✅ Signature valid: {is_valid}")
    
    # Verify with tampered message
    print("\n5. Testing with tampered message...")
    tampered = message + " (tampered)"
    is_valid_tampered = rsa_verify(tampered, signature, keypair['public_key'])
    print(f"   ❌ Tampered message verification: {is_valid_tampered}")

def test_rsa_encryption():
    """Test RSA encryption/decryption"""
    print("\n" + "="*60)
    print("Testing RSA Encryption/Decryption")
    print("="*60)
    
    # Generate keys
    print("\n1. Generating RSA key pair...")
    keypair = generate_rsa_keypair(bits=1024)
    
    # Test data (simulating DES key)
    plaintext = "AABB09182736CCDD"  # 16-char hex DES key
    print(f"\n2. Original data: '{plaintext}'")
    
    # Encrypt
    print("\n3. Encrypting with public key...")
    ciphertext = rsa_encrypt(plaintext, keypair['public_key'])
    print(f"   Ciphertext (first 50 chars): {ciphertext[:50]}...")
    
    # Decrypt
    print("\n4. Decrypting with private key...")
    decrypted = rsa_decrypt(ciphertext, keypair['private_key'])
    print(f"   Decrypted: '{decrypted}'")
    
    # Verify
    if decrypted == plaintext:
        print("\n   ✅ Encryption/Decryption successful!")
    else:
        print("\n   ❌ Encryption/Decryption failed!")

def demo_full_workflow():
    """Demonstrate full signature workflow"""
    print("\n" + "="*60)
    print("FULL DIGITAL SIGNATURE WORKFLOW DEMO")
    print("="*60)
    
    # 1. CA generates keys
    print("\n📋 STEP 1: Certificate Authority generates key pair")
    ca_keys = generate_rsa_keypair(bits=1024)
    print("   CA keys generated!")
    
    # 2. Client generates keys
    print("\n📋 STEP 2: Client 'Alice' generates key pair")
    alice_keys = generate_rsa_keypair(bits=1024)
    print("   Alice's keys generated!")
    
    # 3. CA issues certificate
    print("\n📋 STEP 3: CA issues certificate for Alice")
    from datetime import datetime, timedelta
    
    cert_data = {
        'certificate_id': 'CERT-001',
        'subject': 'Alice',
        'public_key': export_public_key(alice_keys['public_key']),
        'issued_at': datetime.now().isoformat(),
        'expires_at': (datetime.now() + timedelta(days=365)).isoformat(),
        'issuer': 'Manual RSA Certificate Authority'
    }
    
    # CA signs the certificate
    ca_signature = sign_certificate_data(cert_data, ca_keys['private_key'])
    
    certificate = {
        **cert_data,
        'ca_signature': ca_signature,
        'ca_public_key': export_public_key(ca_keys['public_key'])
    }
    print(f"   Certificate issued for: {certificate['subject']}")
    print(f"   Certificate ID: {certificate['certificate_id']}")
    
    # 4. Verify certificate
    print("\n📋 STEP 4: Verify certificate signature")
    is_cert_valid = verify_certificate_signature(certificate, ca_keys['public_key'])
    print(f"   Certificate valid: {'✅' if is_cert_valid else '❌'}")
    
    # 5. Alice signs a message
    print("\n📋 STEP 5: Alice signs a message")
    message = "I, Alice, authorize the transfer of $1000 to Bob."
    signature = rsa_sign(message, alice_keys['private_key'])
    print(f"   Message: '{message}'")
    print(f"   Signature created!")
    
    # 6. Anyone can verify
    print("\n📋 STEP 6: Verify Alice's signature using her certificate")
    alice_public_key = import_public_key(certificate['public_key'])
    is_sig_valid = rsa_verify(message, signature, alice_public_key)
    print(f"   Signature valid: {'✅' if is_sig_valid else '❌'}")
    
    # 7. Non-repudiation demo
    print("\n📋 STEP 7: Non-repudiation demonstration")
    print("   Alice cannot deny signing this message because:")
    print("   - Only Alice has her private key")
    print("   - The signature was verified with her public key")
    print("   - Her public key is certified by the CA")
    
    print("\n" + "="*60)
    print("✅ DEMO COMPLETE - Manual RSA Signature Implementation Working!")
    print("="*60)


if __name__ == "__main__":
    # Run all tests
    test_sha256()
    test_rsa_signature()
    test_rsa_encryption()
    demo_full_workflow()
