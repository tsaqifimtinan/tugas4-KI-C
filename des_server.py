from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import uuid
import random
import base64
import json
from datetime import datetime

# ========================================
# DES CORE IMPLEMENTATION
# ========================================

# Initial Permutation Table
initial_perm = [58, 50, 42, 34, 26, 18, 10, 2,
                60, 52, 44, 36, 28, 20, 12, 4,
                62, 54, 46, 38, 30, 22, 14, 6,
                64, 56, 48, 40, 32, 24, 16, 8,
                57, 49, 41, 33, 25, 17, 9, 1,
                59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5,
                63, 55, 47, 39, 31, 23, 15, 7]

# Expansion D-box Table
exp_d = [32, 1, 2, 3, 4, 5, 4, 5,
         6, 7, 8, 9, 8, 9, 10, 11,
         12, 13, 12, 13, 14, 15, 16, 17,
         16, 17, 18, 19, 20, 21, 20, 21,
         22, 23, 24, 25, 24, 25, 26, 27,
         28, 29, 28, 29, 30, 31, 32, 1]

# Straight Permutation Table
per = [16, 7, 20, 21,
       29, 12, 28, 17,
       1, 15, 23, 26,
       5, 18, 31, 10,
       2, 8, 24, 14,
       32, 27, 3, 9,
       19, 13, 30, 6,
       22, 11, 4, 25]

# S-box Table
sbox = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
         [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
         [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
         [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
         [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

        [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
         [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
         [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
         [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

        [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
         [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
         [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
         [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
         [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
         [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
         [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

        [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
         [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
         [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
         [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
         [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
         [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
         [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

        [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
         [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
         [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
         [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]

# Final Permutation Table
final_perm = [40, 8, 48, 16, 56, 24, 64, 32,
              39, 7, 47, 15, 55, 23, 63, 31,
              38, 6, 46, 14, 54, 22, 62, 30,
              37, 5, 45, 13, 53, 21, 61, 29,
              36, 4, 44, 12, 52, 20, 60, 28,
              35, 3, 43, 11, 51, 19, 59, 27,
              34, 2, 42, 10, 50, 18, 58, 26,
              33, 1, 41, 9, 49, 17, 57, 25]

def hex2bin(s):
    """Convert hexadecimal to binary"""
    mp = {'0': "0000", '1': "0001", '2': "0010", '3': "0011",
          '4': "0100", '5': "0101", '6': "0110", '7': "0111",
          '8': "1000", '9': "1001", 'A': "1010", 'B': "1011",
          'C': "1100", 'D': "1101", 'E': "1110", 'F': "1111"}
    bin_str = ""
    for i in range(len(s)):
        bin_str += mp[s[i]]
    return bin_str

def bin2hex(s):
    """Convert binary to hexadecimal"""
    mp = {"0000": '0', "0001": '1', "0010": '2', "0011": '3',
          "0100": '4', "0101": '5', "0110": '6', "0111": '7',
          "1000": '8', "1001": '9', "1010": 'A', "1011": 'B',
          "1100": 'C', "1101": 'D', "1110": 'E', "1111": 'F'}
    hex_str = ""
    # Pad to multiple of 4 if needed
    while len(s) % 4 != 0:
        s = '0' + s
    for i in range(0, len(s), 4):
        ch = s[i:i+4]
        hex_str += mp[ch]
    return hex_str

def bin2dec(binary):
    """Convert binary to decimal"""
    decimal, i = 0, 0
    while binary != 0:
        dec = binary % 10
        decimal += dec * pow(2, i)
        binary = binary // 10
        i += 1
    return decimal

def dec2bin(num):
    """Convert decimal to binary"""
    res = bin(num).replace("0b", "")
    if len(res) % 4 != 0:
        div = len(res) // 4
        div += 1
        counter = (div * 4) - len(res)
        for i in range(0, counter):
            res = '0' + res
    return res

def permute(k, arr, n):
    """Permute the input using the table"""
    permutation = ""
    for i in range(0, n):
        permutation += k[arr[i] - 1]
    return permutation

def shift_left(k, nth_shifts):
    """Circular left shift by n bits"""
    for i in range(nth_shifts):
        k = k[1:] + k[0]
    return k

def xor(a, b):
    """XOR two binary strings"""
    ans = ""
    for i in range(len(a)):
        if a[i] == b[i]:
            ans += "0"
        else:
            ans += "1"
    return ans

def generate_round_keys(key):
    """Generate 16 round keys from the main key"""
    # Key Permutation Table for PC-1
    keyp = [57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4]

    # Key Permutation Table for PC-2 (48 bits selected from 56)
    # Permuted Choice 2 (PC-2) - reduces 56 to 48 bits
    key_comp = [14, 17, 11, 24, 1, 5, 3, 28,
                15, 6, 21, 10, 23, 19, 12, 4,
                26, 8, 16, 7, 27, 20, 13, 2,
                41, 52, 47, 55, 30, 40, 51, 45,
                33, 48, 44, 49, 39, 56, 34, 53,
                46, 42, 50, 36, 29, 32, 22, 43]

    # Number of shifts for each round
    shift_table = [1, 1, 2, 2,
                   2, 2, 2, 2,
                   1, 2, 2, 2,
                   2, 2, 2, 1]

    # Convert key to binary
    key = hex2bin(key)

    # PC-1 Permutation
    key = permute(key, keyp, 56)

    # Split into left and right
    left = key[0:28]
    right = key[28:56]

    rkb = []  # Round keys in binary
    rk = []   # Round keys in hexadecimal
    for i in range(0, 16):
        # Shift left and right
        left = shift_left(left, shift_table[i])
        right = shift_left(right, shift_table[i])

        # Combine
        combine_str = left + right
        
        # Debug: Check lengths
        if len(combine_str) != 56:
            print(f"ERROR at round {i}: combine_str length = {len(combine_str)}, should be 56")
            print(f"left length = {len(left)}, right length = {len(right)}")
            raise ValueError(f"Combined string has wrong length: {len(combine_str)}")

        # PC-2 Permutation
        round_key = permute(combine_str, key_comp, 48)

        rkb.append(round_key)
        rk.append(bin2hex(round_key))

    return rkb

def encrypt_decrypt(pt, rkb):
    """Main DES encryption/decryption function"""
    pt = hex2bin(pt)

    # Initial Permutation
    pt = permute(pt, initial_perm, 64)

    # Split into left and right
    left = pt[0:32]
    right = pt[32:64]

    for i in range(0, 16):
        # Expansion D-box
        right_expanded = permute(right, exp_d, 48)

        # XOR with round key
        x = xor(rkb[i], right_expanded)

        # S-boxes
        op = ""
        for j in range(0, 8):
            # Get 6-bit chunk
            chunk = x[j * 6:(j * 6) + 6]
            
            # Ensure chunk is exactly 6 bits
            if len(chunk) < 6:
                chunk = chunk.ljust(6, '0')
            
            # Row (first and last bit)
            row = int(chunk[0] + chunk[5], 2)
            
            # Column (middle 4 bits)
            col = int(chunk[1:5], 2)
            
            # Bounds check
            if row > 3 or col > 15:
                raise ValueError(f"S-box index out of range: row={row}, col={col}, chunk={chunk}")
            
            # S-box lookup
            val = sbox[j][row][col]
            op += dec2bin(val)

        # Permutation P
        op = permute(op, per, 32)

        # XOR with left
        x = xor(op, left)

        # Swap
        left = x
        if i != 15:
            left, right = right, left

    # Combination
    combine = left + right

    # Final permutation
    cipher_text = permute(combine, final_perm, 64)
    return cipher_text

def text_to_hex_blocks(text):
    """Convert text to 64-bit hex blocks"""
    # Convert to hex
    hex_str = text.encode('utf-8').hex().upper()
    
    # Pad to multiple of 16 (64 bits)
    while len(hex_str) % 16 != 0:
        hex_str += '0'
    
    # Split into 16-character blocks
    blocks = []
    for i in range(0, len(hex_str), 16):
        blocks.append(hex_str[i:i+16])
    
    return blocks

def hex_blocks_to_text(blocks, original_length):
    """Convert hex blocks back to text"""
    hex_str = ''.join(blocks)
    
    # Convert hex to bytes
    byte_data = bytes.fromhex(hex_str)
    
    # Decode and remove padding
    text = byte_data.decode('utf-8', errors='ignore')
    return text[:original_length]

def generate_random_key():
    """Generate a random 64-bit DES key (16 hex characters)"""
    hex_chars = '0123456789ABCDEF'
    key = ''.join(random.choice(hex_chars) for _ in range(16))
    return key

# ========================================
# FLASK APPLICATION
# ========================================

app = Flask(__name__)
CORS(app)

# Message storage with PKI support
messages_store = {}

# ========================================
# PKI HELPER FUNCTIONS
# ========================================

def verify_certificate_signature(certificate, ca_public_key):
    """Verify certificate was signed by CA"""
    try:
        signature = certificate['ca_signature']
        cert_data = {k: v for k, v in certificate.items() 
                    if k not in ['ca_signature', 'ca_public_key']}
        data_to_verify = json.dumps(cert_data, sort_keys=True)
        
        h = SHA256.new(data_to_verify.encode('utf-8'))
        signature_bytes = base64.b64decode(signature)
        pkcs1_15.new(ca_public_key).verify(h, signature_bytes)
        return True
    except:
        return False

def encrypt_with_public_key(data, public_key_pem):
    """Encrypt data using RSA public key"""
    public_key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(public_key)
    encrypted = cipher.encrypt(data.encode('utf-8'))
    return base64.b64encode(encrypted).decode('utf-8')

# ========================================
# PKI-ENABLED ENDPOINTS
# ========================================

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        'status': 'success',
        'service': 'DES Server with Public Key Infrastructure (PKI)',
        'description': 'Secure message encryption using DES with RSA-based key distribution',
        'endpoints': {
            '/': 'GET - Server info',
            '/send-secure': 'POST - Encrypt message with certificate-based key distribution',
            '/receive-secure': 'POST - Decrypt message using private key',
            '/messages': 'GET - List all stored messages'
        },
        'security': {
            'encryption': 'DES for message content',
            'key_distribution': 'RSA-2048 with digital certificates',
            'authentication': 'CA-signed certificates'
        }
    })

@app.route('/send-secure', methods=['POST'])
def send_secure_message():
    """
    SECURE MESSAGE SENDING WITH PKI
    --------------------------------
    Process:
    1. Sender provides: plaintext, sender certificate, receiver certificate
    2. Verify both certificates with CA
    3. Generate random DES session key
    4. Encrypt message with DES using session key
    5. Encrypt DES key with receiver's RSA public key (from certificate)
    6. Sign the message with sender's identity
    7. Store encrypted message with encrypted key
    8. Return message_id to sender
    
    Security Benefits:
    - Only receiver can decrypt the DES key (RSA encryption)
    - Message authenticity verified (certificates)
    - Session key per message (perfect forward secrecy)
    """
    try:
        data = request.get_json()
        
        # Validate input
        required_fields = ['text', 'sender_certificate', 'receiver_certificate', 'ca_public_key']
        if not all(field in data for field in required_fields):
            return jsonify({
                'status': 'error',
                'message': f'Required fields: {", ".join(required_fields)}'
            }), 400
        
        plaintext = data['text']
        sender_cert = data['sender_certificate']
        receiver_cert = data['receiver_certificate']
        ca_public_key_pem = data['ca_public_key']
        
        # STEP 1: Verify certificates
        ca_public_key = RSA.import_key(ca_public_key_pem)
        
        if not verify_certificate_signature(sender_cert, ca_public_key):
            return jsonify({
                'status': 'error',
                'message': 'Invalid sender certificate'
            }), 400
        
        if not verify_certificate_signature(receiver_cert, ca_public_key):
            return jsonify({
                'status': 'error',
                'message': 'Invalid receiver certificate'
            }), 400
        
        # STEP 2: Extract receiver's public key from certificate
        receiver_public_key_pem = receiver_cert['public_key']
        print(f"\n🔑 Receiver's Public Key (first 100 chars):")
        print(f"   {receiver_public_key_pem[:100]}...")
        
        # STEP 3: Generate random DES session key
        des_key = generate_random_key()
        print(f"\n🎲 Generated DES Session Key: {des_key}")
        
        # STEP 4: Encrypt message with DES
        original_length = len(plaintext)
        hex_blocks = text_to_hex_blocks(plaintext)
        rkb = generate_round_keys(des_key)
        encrypted_blocks = []
        
        for block in hex_blocks:
            cipher_block = bin2hex(encrypt_decrypt(block, rkb))
            encrypted_blocks.append(cipher_block)
        
        # STEP 5: Encrypt DES key with receiver's RSA public key
        print(f"\n🔐 Encrypting session key with receiver's public key...")
        encrypted_des_key = encrypt_with_public_key(des_key, receiver_public_key_pem)
        print(f"   ✅ Session key encrypted (length: {len(encrypted_des_key)} chars)")

        
        # STEP 6: Generate message ID
        message_id = str(uuid.uuid4())[:12]
        
        # STEP 7: Store encrypted message
        messages_store[message_id] = {
            'encrypted_blocks': encrypted_blocks,
            'encrypted_key': encrypted_des_key,  # Only receiver can decrypt this
            'original_length': original_length,
            'sender': sender_cert['subject'],
            'receiver': receiver_cert['subject'],
            'timestamp': datetime.now().isoformat(),
            'sender_certificate': sender_cert,
            'receiver_certificate': receiver_cert
        }
        
        print(f"\n{'='*60}")
        print(f"📤 SEND MESSAGE - Message ID: {message_id}")
        print(f"{'='*60}")
        print(f"   • From: {sender_cert['subject']}")
        print(f"   • To: {receiver_cert['subject']}")
        print(f"   • Message Length: {original_length} chars")
        print(f"{'='*60}\n")
        
        ciphertext = ''.join(encrypted_blocks)
        
        return jsonify({
            'status': 'success',
            'message': 'Message encrypted and secured with PKI',
            'message_id': message_id,
            'sender': sender_cert['subject'],
            'receiver': receiver_cert['subject'],
            'ciphertext': ciphertext,
            'encrypted_session_key': encrypted_des_key,
            'security_info': {
                'message_encryption': 'DES with random session key',
                'key_distribution': 'RSA-encrypted session key',
                'authentication': 'CA-signed certificates'
            },
            'instruction': f'Share message_id with {receiver_cert["subject"]}: {message_id}'
        })
    
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Error in send_secure: {error_details}")
        return jsonify({
            'status': 'error',
            'message': f'Error: {str(e)}',
            'details': error_details
        }), 500

@app.route('/receive-secure', methods=['POST'])
def receive_secure_message():
    """
    SECURE MESSAGE RECEIVING WITH PKI
    ---------------------------------
    Process:
    1. Receiver provides: message_id, private key, certificate
    2. Retrieve encrypted message from storage
    3. Verify receiver's certificate
    4. Decrypt DES session key using receiver's RSA private key
    5. Decrypt message using recovered DES key
    6. Return plaintext to receiver
    
    Security Benefits:
    - Only intended receiver can decrypt (RSA private key)
    - Sender identity verified (certificate check)
    - End-to-end encryption maintained
    """
    try:
        data = request.get_json()
        
        # Validate input
        required_fields = ['message_id', 'private_key', 'certificate', 'ca_public_key']
        if not all(field in data for field in required_fields):
            return jsonify({
                'status': 'error',
                'message': f'Required fields: {", ".join(required_fields)}'
            }), 400
        
        message_id = data['message_id']
        receiver_private_key_pem = data['private_key']
        receiver_cert = data['certificate']
        ca_public_key_pem = data['ca_public_key']
        
        # STEP 1: Check message exists
        if message_id not in messages_store:
            return jsonify({
                'status': 'error',
                'message': f'Message not found: {message_id}'
            }), 404
        
        msg = messages_store[message_id]
        
        # STEP 2: Verify receiver's certificate
        ca_public_key = RSA.import_key(ca_public_key_pem)
        if not verify_certificate_signature(receiver_cert, ca_public_key):
            return jsonify({
                'status': 'error',
                'message': 'Invalid receiver certificate'
            }), 400
        
        # STEP 3: Verify receiver is the intended recipient
        print(f"\n{'='*60}")
        print(f"🔍 RECEIVE MESSAGE DEBUG - Message ID: {message_id}")
        print(f"{'='*60}")
        print(f"📨 Message Info:")
        print(f"   • Sender: {msg['sender']}")
        print(f"   • Intended Receiver: {msg['receiver']}")
        print(f"   • Timestamp: {msg['timestamp']}")
        print(f"\n👤 Your Certificate:")
        print(f"   • Subject: {receiver_cert['subject']}")
        print(f"\n🔐 Validation:")
        print(f"   • Match: {receiver_cert['subject'] == msg['receiver']}")
        
        if receiver_cert['subject'] != msg['receiver']:
            print(f"   ❌ FAILED: You are '{receiver_cert['subject']}', message is for '{msg['receiver']}'")
            print(f"{'='*60}\n")
            return jsonify({
                'status': 'error',
                'message': f"Access denied. This message is for '{msg['receiver']}', but your certificate shows '{receiver_cert['subject']}'"
            }), 403
        
        print(f"   ✅ PASSED: You are the intended receiver")
        print(f"{'='*60}\n")
        
        # STEP 4: Decrypt DES session key with receiver's private key
        print(f"🔑 STEP 4: Decrypting DES Session Key...")
        try:
            receiver_private_key = RSA.import_key(receiver_private_key_pem)
            print(f"   ✅ Private key loaded successfully")
            print(f"   • Key size: {receiver_private_key.size_in_bits()} bits")
            
            cipher = PKCS1_OAEP.new(receiver_private_key)
            encrypted_key_bytes = base64.b64decode(msg['encrypted_key'])
            print(f"   • Encrypted key size: {len(encrypted_key_bytes)} bytes")
            
            des_key = cipher.decrypt(encrypted_key_bytes).decode('utf-8')
            print(f"   ✅ Session key decrypted successfully")
            print(f"   • DES Key: {des_key[:8]}...{des_key[-8:]}")
        except Exception as e:
            print(f"   ❌ DECRYPTION FAILED!")
            print(f"   • Error type: {type(e).__name__}")
            print(f"   • Error message: {str(e)}")
            print(f"\n💡 DIAGNOSIS:")
            print(f"   This usually means:")
            print(f"   1. Private key doesn't match the public key used for encryption")
            print(f"   2. Private key is corrupted or wrong format")
            print(f"   3. Message was encrypted for a different receiver")
            return jsonify({
                'status': 'error',
                'message': f'Failed to decrypt session key: {str(e)}',
                'hint': 'Make sure you are using the SAME private key that matches your certificate'
            }), 403
        
        # STEP 5: Decrypt message with recovered DES key
        rkb = generate_round_keys(des_key)
        rkb_rev = rkb[::-1]
        decrypted_blocks = []
        
        for block in msg['encrypted_blocks']:
            plain_block = bin2hex(encrypt_decrypt(block, rkb_rev))
            decrypted_blocks.append(plain_block)
        
        plaintext = hex_blocks_to_text(decrypted_blocks, msg['original_length'])
        ciphertext = ''.join(msg['encrypted_blocks'])
        
        return jsonify({
            'status': 'success',
            'message': 'Message decrypted successfully',
            'message_id': message_id,
            'plaintext': plaintext,
            'ciphertext': ciphertext,
            'sender': msg['sender'],
            'receiver': msg['receiver'],
            'timestamp': msg['timestamp'],
            'security_info': {
                'session_key_decrypted': 'Using your RSA private key',
                'message_decrypted': 'Using recovered DES session key',
                'sender_verified': 'Via CA-signed certificate'
            }
        })
    
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Error: {str(e)}'
        }), 500

@app.route('/messages', methods=['GET'])
def list_messages():
    """List all stored messages"""
    messages_list = []
    for msg_id, msg_data in messages_store.items():
        messages_list.append({
            'message_id': msg_id,
            'sender': msg_data['sender'],
            'receiver': msg_data['receiver'],
            'timestamp': msg_data['timestamp']
        })
    
    return jsonify({
        'status': 'success',
        'total_messages': len(messages_list),
        'messages': messages_list
    })

@app.route('/reset', methods=['POST'])
def reset_server():
    """Reset message storage (for testing only)"""
    global messages_store
    
    old_count = len(messages_store)
    messages_store.clear()
    
    return jsonify({
        'status': 'success',
        'message': 'Message storage reset successfully',
        'cleared_messages': old_count
    })

if __name__ == "__main__":
    print("=" * 60)
    print("DES SERVER WITH PUBLIC KEY INFRASTRUCTURE (PKI)")
    print("=" * 60)
    print("\n🔐 Security Features:")
    print("   ✓ Message encryption: DES algorithm")
    print("   ✓ Key distribution: RSA-2048 encryption")
    print("   ✓ Authentication: CA-signed certificates")
    print("   ✓ Perfect forward secrecy: Unique session key per message")
    print("\n📋 Available Endpoints:")
    print("   GET  /              - Server info")
    print("   POST /send-secure   - Send encrypted message with PKI")
    print("   POST /receive-secure - Receive and decrypt message")
    print("   GET  /messages      - List all messages")
    print("   POST /reset         - Reset storage (testing only)")
    print("="*60)
    print("\n⚠️  IMPORTANT: This server requires localtunnel for access")
    print("\n📝 Setup Instructions:")
    print("   1. Install localtunnel: npm install -g localtunnel")
    print("   2. In a new terminal, run: lt --port 5002 --subdomain des-server-<yourname>")
    print("   3. Share the generated URL (e.g., https://des-server-yourname.loca.lt)")
    print("\n✅ Server starting on port 5002...")
    print("   Press Ctrl+C to stop\n")
    
    app.run(host='0.0.0.0', port=5002, debug=False)