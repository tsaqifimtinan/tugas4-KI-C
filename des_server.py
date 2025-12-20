from flask import Flask, request, jsonify
from flask_cors import CORS
import uuid
import random
from datetime import datetime

# Import manual RSA implementation
from rsa_signature import (
    rsa_sign,
    rsa_verify,
    rsa_encrypt,
    rsa_decrypt,
    import_public_key,
    import_private_key,
    verify_certificate_signature,
)

# ========================================
# DES CORE IMPLEMENTATION (Existing)
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
        bin_str += mp[s[i].upper()]
    return bin_str

def bin2hex(s):
    """Convert binary to hexadecimal"""
    mp = {"0000": '0', "0001": '1', "0010": '2', "0011": '3',
          "0100": '4', "0101": '5', "0110": '6', "0111": '7',
          "1000": '8', "1001": '9', "1010": 'A', "1011": 'B',
          "1100": 'C', "1101": 'D', "1110": 'E', "1111": 'F'}
    hex_str = ""
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
    keyp = [57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4]

    key_comp = [14, 17, 11, 24, 1, 5, 3, 28,
                15, 6, 21, 10, 23, 19, 12, 4,
                26, 8, 16, 7, 27, 20, 13, 2,
                41, 52, 47, 55, 30, 40, 51, 45,
                33, 48, 44, 49, 39, 56, 34, 53,
                46, 42, 50, 36, 29, 32, 22, 43]

    shift_table = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    key = hex2bin(key)
    key = permute(key, keyp, 56)

    left = key[0:28]
    right = key[28:56]

    rkb = []
    for i in range(0, 16):
        left = shift_left(left, shift_table[i])
        right = shift_left(right, shift_table[i])
        combine_str = left + right
        round_key = permute(combine_str, key_comp, 48)
        rkb.append(round_key)

    return rkb

def encrypt_decrypt(pt, rkb):
    """Main DES encryption/decryption function"""
    pt = hex2bin(pt)
    pt = permute(pt, initial_perm, 64)

    left = pt[0:32]
    right = pt[32:64]

    for i in range(0, 16):
        right_expanded = permute(right, exp_d, 48)
        x = xor(rkb[i], right_expanded)

        op = ""
        for j in range(0, 8):
            chunk = x[j * 6:(j * 6) + 6]
            if len(chunk) < 6:
                chunk = chunk.ljust(6, '0')
            row = int(chunk[0] + chunk[5], 2)
            col = int(chunk[1:5], 2)
            val = sbox[j][row][col]
            op += dec2bin(val)

        op = permute(op, per, 32)
        x = xor(op, left)
        left = x
        if i != 15:
            left, right = right, left

    combine = left + right
    cipher_text = permute(combine, final_perm, 64)
    return cipher_text

def text_to_hex_blocks(text):
    """Convert text to 64-bit hex blocks"""
    hex_str = text.encode('utf-8').hex().upper()
    while len(hex_str) % 16 != 0:
        hex_str += '0'
    blocks = []
    for i in range(0, len(hex_str), 16):
        blocks.append(hex_str[i:i+16])
    return blocks

def hex_blocks_to_text(blocks, original_length):
    """Convert hex blocks back to text"""
    hex_str = ''.join(blocks)
    byte_data = bytes.fromhex(hex_str)
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

def verify_cert_signature(certificate, ca_public_key_json):
    """Verify certificate was signed by CA using manual RSA"""
    try:
        ca_public_key = import_public_key(ca_public_key_json)
        return verify_certificate_signature(certificate, ca_public_key)
    except Exception as e:
        print(f"Certificate verification error: {e}")
        return False

def encrypt_with_public_key_manual(data, public_key_json):
    """Encrypt data using manual RSA public key"""
    public_key = import_public_key(public_key_json)
    return rsa_encrypt(data, public_key)

def decrypt_with_private_key_manual(ciphertext, private_key_json):
    """Decrypt data using manual RSA private key"""
    private_key = import_private_key(private_key_json)
    return rsa_decrypt(ciphertext, private_key)

def sign_message_manual(message, private_key_json):
    """Sign message using manual RSA"""
    private_key = import_private_key(private_key_json)
    return rsa_sign(message, private_key)

def verify_signature_manual(message, signature, public_key_json):
    """Verify signature using manual RSA"""
    public_key = import_public_key(public_key_json)
    return rsa_verify(message, signature, public_key)

# ========================================
# PKI-ENABLED ENDPOINTS
# ========================================

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        'status': 'success',
        'service': 'DES Server with Manual RSA Implementation',
        'description': 'Secure message encryption using DES with manual RSA key distribution',
        'implementation': 'NO external crypto library - all RSA operations manual',
        'endpoints': {
            '/': 'GET - Server info',
            '/send-secure': 'POST - Encrypt and SIGN message with PKI',
            '/receive-secure': 'POST - Decrypt and VERIFY message',
            '/sign': 'POST - Sign a document (no encryption)',
            '/verify-signature': 'POST - Verify a signature',
            '/messages': 'GET - List all stored messages'
        },
        'security': {
            'encryption': 'DES for message content',
            'key_distribution': 'Manual RSA encryption',
            'authentication': 'CA-signed certificates (manual RSA)',
            'digital_signature': 'Manual RSA-SHA256 for non-repudiation'
        }
    })

@app.route('/send-secure', methods=['POST'])
def send_secure_message():
    """
    SECURE MESSAGE SENDING WITH PKI AND DIGITAL SIGNATURE
    ------------------------------------------------------
    Process:
    1. Sender provides: plaintext, sender certificate, receiver certificate, sender private key
    2. Verify both certificates with CA (manual RSA)
    3. Generate random DES session key
    4. Encrypt message with DES using session key
    5. Encrypt DES key with receiver's RSA public key (manual RSA)
    6. SIGN the message with sender's RSA private key (manual RSA - NON-REPUDIATION)
    7. Store encrypted message with encrypted key and signature
    8. Return message_id to sender
    
    Security Benefits:
    - Only receiver can decrypt the DES key
    - Message authenticity verified via certificates
    - Session key per message (perfect forward secrecy)
    - DIGITAL SIGNATURE proves sender identity (non-repudiation)
    - ALL RSA operations done manually
    """
    try:
        data = request.get_json()
        
        # Validate input
        required_fields = ['text', 'sender_certificate', 'receiver_certificate', 'ca_public_key', 'sender_private_key']
        if not all(field in data for field in required_fields):
            return jsonify({
                'status': 'error',
                'message': f'Required fields: {", ".join(required_fields)}'
            }), 400
        
        plaintext = data['text']
        sender_cert = data['sender_certificate']
        receiver_cert = data['receiver_certificate']
        ca_public_key_json = data['ca_public_key']
        sender_private_key_json = data['sender_private_key']
        
        # STEP 1: Verify certificates (using manual RSA)
        print(f"\n🔐 Verifying certificates (Manual RSA)...")
        
        if not verify_cert_signature(sender_cert, ca_public_key_json):
            return jsonify({
                'status': 'error',
                'message': 'Invalid sender certificate (manual RSA verification failed)'
            }), 400
        print("   ✅ Sender certificate verified")
        
        if not verify_cert_signature(receiver_cert, ca_public_key_json):
            return jsonify({
                'status': 'error',
                'message': 'Invalid receiver certificate (manual RSA verification failed)'
            }), 400
        print("   ✅ Receiver certificate verified")
        
        # STEP 2: Extract receiver's public key from certificate
        receiver_public_key_json = receiver_cert['public_key']
        
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
        
        # STEP 5: Encrypt DES key with receiver's RSA public key (MANUAL)
        print(f"\n🔐 Encrypting session key (Manual RSA)...")
        encrypted_des_key = encrypt_with_public_key_manual(des_key, receiver_public_key_json)
        print(f"   ✅ Session key encrypted")

        # STEP 6: Create digital signature (MANUAL RSA)
        print(f"\n✍️  Creating digital signature (Manual RSA-SHA256)...")
        message_signature = sign_message_manual(plaintext, sender_private_key_json)
        print(f"   ✅ Message signed (signature length: {len(message_signature)} chars)")
        
        # STEP 7: Generate message ID
        message_id = str(uuid.uuid4())[:12]
        
        # STEP 8: Store encrypted message with signature
        messages_store[message_id] = {
            'encrypted_blocks': encrypted_blocks,
            'encrypted_key': encrypted_des_key,
            'original_length': original_length,
            'sender': sender_cert['subject'],
            'receiver': receiver_cert['subject'],
            'timestamp': datetime.now().isoformat(),
            'sender_certificate': sender_cert,
            'receiver_certificate': receiver_cert,
            'message_signature': message_signature
        }
        
        print(f"\n{'='*60}")
        print(f"📤 SEND MESSAGE - Message ID: {message_id}")
        print(f"{'='*60}")
        print(f"   • From: {sender_cert['subject']}")
        print(f"   • To: {receiver_cert['subject']}")
        print(f"   • Message Length: {original_length} chars")
        print(f"   • Digitally Signed: ✅ (Manual RSA)")
        print(f"{'='*60}\n")
        
        ciphertext = ''.join(encrypted_blocks)
        
        return jsonify({
            'status': 'success',
            'message': 'Message encrypted, signed, and secured (Manual RSA)',
            'message_id': message_id,
            'sender': sender_cert['subject'],
            'receiver': receiver_cert['subject'],
            'ciphertext': ciphertext,
            'encrypted_session_key': encrypted_des_key,
            'message_signature': message_signature,
            'security_info': {
                'message_encryption': 'DES with random session key',
                'key_distribution': 'Manual RSA-encrypted session key',
                'authentication': 'CA-signed certificates (Manual RSA)',
                'non_repudiation': 'Manual RSA-SHA256 digital signature'
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
    SECURE MESSAGE RECEIVING WITH PKI AND SIGNATURE VERIFICATION
    -------------------------------------------------------------
    Process:
    1. Receiver provides: message_id, private key, certificate
    2. Retrieve encrypted message from storage
    3. Verify receiver's certificate (manual RSA)
    4. Decrypt DES session key using receiver's RSA private key (manual RSA)
    5. Decrypt message using recovered DES key
    6. VERIFY sender's digital signature (manual RSA)
    7. Return plaintext with verification status
    
    Security Benefits:
    - Only intended receiver can decrypt
    - Sender identity verified
    - NON-REPUDIATION: Sender cannot deny sending the message
    - ALL RSA operations done manually
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
        receiver_private_key_json = data['private_key']
        receiver_cert = data['certificate']
        ca_public_key_json = data['ca_public_key']
        
        # STEP 1: Check message exists
        if message_id not in messages_store:
            return jsonify({
                'status': 'error',
                'message': f'Message not found: {message_id}'
            }), 404
        
        msg = messages_store[message_id]
        
        # STEP 2: Verify receiver's certificate (manual RSA)
        if not verify_cert_signature(receiver_cert, ca_public_key_json):
            return jsonify({
                'status': 'error',
                'message': 'Invalid receiver certificate'
            }), 400
        
        # STEP 3: Verify receiver is the intended recipient
        if receiver_cert['subject'] != msg['receiver']:
            return jsonify({
                'status': 'error',
                'message': f"Access denied. Message is for '{msg['receiver']}'"
            }), 403
        
        # STEP 4: Decrypt DES session key with manual RSA
        print(f"\n🔑 Decrypting DES Session Key (Manual RSA)...")
        try:
            des_key = decrypt_with_private_key_manual(msg['encrypted_key'], receiver_private_key_json)
            print(f"   ✅ Session key decrypted: {des_key}")
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': f'Failed to decrypt session key: {str(e)}'
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
        
        # STEP 6: Verify sender's digital signature (Manual RSA)
        print(f"\n✍️  Verifying digital signature (Manual RSA-SHA256)...")
        signature_valid = False
        signature_status = "No signature found"
        
        if 'message_signature' in msg:
            sender_public_key_json = msg['sender_certificate']['public_key']
            signature_valid = verify_signature_manual(
                plaintext, 
                msg['message_signature'], 
                sender_public_key_json
            )
            if signature_valid:
                signature_status = "✅ VERIFIED - Sender identity confirmed (Manual RSA)"
                print(f"   {signature_status}")
            else:
                signature_status = "❌ INVALID - Signature verification failed!"
                print(f"   {signature_status}")
        else:
            print(f"   ⚠️  No signature found")
        
        return jsonify({
            'status': 'success',
            'message': 'Message decrypted successfully',
            'message_id': message_id,
            'plaintext': plaintext,
            'ciphertext': ciphertext,
            'sender': msg['sender'],
            'receiver': msg['receiver'],
            'timestamp': msg['timestamp'],
            'signature_verification': {
                'valid': signature_valid,
                'status': signature_status,
                'non_repudiation': signature_valid,
                'algorithm': 'Manual RSA-SHA256'
            },
            'security_info': {
                'session_key_decrypted': 'Using Manual RSA',
                'message_decrypted': 'Using DES',
                'sender_verified': 'Via CA certificate (Manual RSA)',
                'signature_verified': signature_valid
            }
        })
    
    except Exception as e:
        import traceback
        return jsonify({
            'status': 'error',
            'message': f'Error: {str(e)}',
            'traceback': traceback.format_exc()
        }), 500

@app.route('/sign', methods=['POST'])
def sign_document():
    """
    STANDALONE DIGITAL SIGNATURE (Manual RSA)
    -----------------------------------------
    Sign any document without encryption.
    """
    try:
        data = request.get_json()
        
        required_fields = ['message', 'private_key', 'certificate', 'ca_public_key']
        if not all(field in data for field in required_fields):
            return jsonify({
                'status': 'error',
                'message': f'Required fields: {", ".join(required_fields)}'
            }), 400
        
        message = data['message']
        private_key_json = data['private_key']
        certificate = data['certificate']
        ca_public_key_json = data['ca_public_key']
        
        # Verify certificate
        if not verify_cert_signature(certificate, ca_public_key_json):
            return jsonify({
                'status': 'error',
                'message': 'Invalid certificate'
            }), 400
        
        # Create signature (Manual RSA)
        signature = sign_message_manual(message, private_key_json)
        
        return jsonify({
            'status': 'success',
            'message': 'Document signed successfully (Manual RSA)',
            'original_message': message,
            'signature': signature,
            'signer': certificate['subject'],
            'algorithm': 'Manual RSA-SHA256',
            'timestamp': datetime.now().isoformat()
        })
    
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Signing error: {str(e)}'
        }), 500

@app.route('/verify-signature', methods=['POST'])
def verify_signature_endpoint():
    """
    STANDALONE SIGNATURE VERIFICATION (Manual RSA)
    -----------------------------------------------
    Verify a digital signature on any document.
    """
    try:
        data = request.get_json()
        
        required_fields = ['message', 'signature', 'certificate', 'ca_public_key']
        if not all(field in data for field in required_fields):
            return jsonify({
                'status': 'error',
                'message': f'Required fields: {", ".join(required_fields)}'
            }), 400
        
        message = data['message']
        signature = data['signature']
        certificate = data['certificate']
        ca_public_key_json = data['ca_public_key']
        
        # Verify certificate first
        if not verify_cert_signature(certificate, ca_public_key_json):
            return jsonify({
                'status': 'error',
                'message': 'Invalid certificate',
                'signature_valid': False
            }), 400
        
        # Verify signature (Manual RSA)
        public_key_json = certificate['public_key']
        is_valid = verify_signature_manual(message, signature, public_key_json)
        
        return jsonify({
            'status': 'success' if is_valid else 'failed',
            'signature_valid': is_valid,
            'message': 'Signature is valid (Manual RSA)' if is_valid else 'Signature verification failed',
            'signer': certificate['subject'],
            'verification_details': {
                'certificate_valid': True,
                'signature_matches': is_valid,
                'algorithm': 'Manual RSA-SHA256'
            }
        })
    
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Verification error: {str(e)}',
            'signature_valid': False
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
            'timestamp': msg_data['timestamp'],
            'has_signature': 'message_signature' in msg_data
        })
    
    return jsonify({
        'status': 'success',
        'total_messages': len(messages_list),
        'messages': messages_list
    })

@app.route('/reset', methods=['POST'])
def reset_server():
    """Reset message storage"""
    global messages_store
    old_count = len(messages_store)
    messages_store.clear()
    
    return jsonify({
        'status': 'success',
        'message': 'Message storage reset',
        'cleared_messages': old_count
    })

if __name__ == "__main__":
    print("=" * 60)
    print("DES SERVER WITH MANUAL RSA IMPLEMENTATION")
    print("NO EXTERNAL CRYPTO LIBRARY USED")
    print("=" * 60)
    print("\n🔐 Security Features:")
    print("   ✓ Message encryption: DES algorithm")
    print("   ✓ Key distribution: Manual RSA encryption")
    print("   ✓ Authentication: CA-signed certificates (Manual RSA)")
    print("   ✓ Digital Signature: Manual RSA-SHA256 (Non-repudiation)")
    print("   ✓ Hash function: Manual SHA-256")
    print("\n📋 Available Endpoints:")
    print("   GET  /              - Server info")
    print("   POST /send-secure   - Send encrypted+signed message")
    print("   POST /receive-secure - Receive and verify message")
    print("   POST /sign          - Sign document (no encryption)")
    print("   POST /verify-signature - Verify signature")
    print("   GET  /messages      - List all messages")
    print("="*60)
    print("\n✅ Server starting on port 5002...")
    
    app.run(host='0.0.0.0', port=5002, debug=False)
