"""
Certificate Authority (CA) Server
----------------------------------
Implements Public Key Infrastructure (PKI) for secure key distribution:
- Issues digital certificates to clients
- Signs certificates with CA's private key
- Verifies certificate authenticity
- Maintains certificate registry
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
import base64
import json
import uuid
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app)

# ========================================
# CA KEY PAIR GENERATION
# ========================================
# Generate CA's own RSA key pair (2048-bit for security)
print("Generating Certificate Authority (CA) key pair...")
ca_key = RSA.generate(2048)
ca_private_key = ca_key
ca_public_key = ca_key.publickey()
print("✅ CA keys generated successfully!")

# Certificate storage: {cert_id: certificate_data}
certificates_db = {}
# Client public keys: {client_id: public_key_pem}
client_keys_db = {}

# ========================================
# HELPER FUNCTIONS
# ========================================

def sign_data(data, private_key):
    """Sign data with private key using SHA256"""
    h = SHA256.new(data.encode('utf-8'))
    signature = pkcs1_15.new(private_key).sign(h)
    return base64.b64encode(signature).decode('utf-8')

def verify_signature(data, signature, public_key):
    """Verify signature with public key"""
    try:
        h = SHA256.new(data.encode('utf-8'))
        signature_bytes = base64.b64decode(signature)
        pkcs1_15.new(public_key).verify(h, signature_bytes)
        return True
    except:
        return False

def create_certificate(client_id, client_public_key_pem, validity_days=365):
    """
    Create a digital certificate for a client
    
    Certificate contains:
    - Certificate ID
    - Client ID (subject)
    - Client's public key
    - Validity period
    - CA's digital signature
    """
    cert_id = str(uuid.uuid4())[:12]
    issued_at = datetime.now()
    expires_at = issued_at + timedelta(days=validity_days)
    
    # Certificate data to be signed
    cert_data = {
        'certificate_id': cert_id,
        'subject': client_id,
        'public_key': client_public_key_pem,
        'issued_at': issued_at.isoformat(),
        'expires_at': expires_at.isoformat(),
        'issuer': 'Trusted Certificate Authority'
    }
    
    # Create signature over certificate data
    data_to_sign = json.dumps(cert_data, sort_keys=True)
    signature = sign_data(data_to_sign, ca_private_key)
    
    # Complete certificate with signature
    certificate = {
        **cert_data,
        'ca_signature': signature,
        'ca_public_key': ca_public_key.export_key().decode('utf-8')
    }
    
    return cert_id, certificate

# ========================================
# CA ENDPOINTS
# ========================================

@app.route('/', methods=['GET'])
def home():
    """CA Server information"""
    return jsonify({
        'status': 'success',
        'service': 'Certificate Authority (CA) Server',
        'description': 'Issues and verifies digital certificates for secure key distribution',
        'endpoints': {
            '/ca/info': 'GET - Get CA public key',
            '/ca/register': 'POST - Register client and get certificate',
            '/ca/verify': 'POST - Verify certificate authenticity',
            '/ca/get-cert': 'POST - Get certificate by client_id',
            '/ca/certificates': 'GET - List all certificates'
        },
        'total_certificates': len(certificates_db)
    })

@app.route('/ca/info', methods=['GET'])
def ca_info():
    """
    GET CA PUBLIC KEY
    -----------------
    Returns the CA's public key for signature verification
    """
    return jsonify({
        'status': 'success',
        'ca_public_key': ca_public_key.export_key().decode('utf-8'),
        'key_size': ca_public_key.size_in_bits(),
        'algorithm': 'RSA-2048 with SHA256 signatures'
    })

@app.route('/ca/register', methods=['POST'])
def register_client():
    """
    CLIENT REGISTRATION
    -------------------
    Process:
    1. Client generates RSA key pair
    2. Client sends public key + identity to CA
    3. CA creates digital certificate
    4. CA signs certificate with CA's private key
    5. CA returns certificate to client
    
    The certificate proves ownership of the public key
    """
    try:
        data = request.get_json()
        
        if not data or 'client_id' not in data or 'public_key' not in data:
            return jsonify({
                'status': 'error',
                'message': 'Required: client_id, public_key'
            }), 400
        
        client_id = data['client_id']
        client_public_key_pem = data['public_key']
        
        # Validate public key format
        try:
            RSA.import_key(client_public_key_pem)
        except:
            return jsonify({
                'status': 'error',
                'message': 'Invalid RSA public key format'
            }), 400
        
        # Check if client already registered
        if client_id in client_keys_db:
            # Return existing certificate
            for cert_id, cert in certificates_db.items():
                if cert['subject'] == client_id:
                    return jsonify({
                        'status': 'success',
                        'message': 'Client already registered, returning existing certificate',
                        'certificate_id': cert_id,
                        'certificate': cert,
                        'reused': True
                    })
        
        # Create certificate
        cert_id, certificate = create_certificate(client_id, client_public_key_pem)
        
        # Store certificate and public key
        certificates_db[cert_id] = certificate
        client_keys_db[client_id] = client_public_key_pem
        
        return jsonify({
            'status': 'success',
            'message': 'Certificate issued successfully',
            'certificate_id': cert_id,
            'certificate': certificate,
            'instruction': 'Save this certificate. You will need it for secure communication.'
        })
    
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Registration error: {str(e)}'
        }), 500

@app.route('/ca/verify', methods=['POST'])
def verify_certificate():
    """
    CERTIFICATE VERIFICATION
    ------------------------
    Process:
    1. Receive certificate from client
    2. Extract certificate data and signature
    3. Verify signature using CA's public key
    4. Check expiration date
    5. Return verification result
    
    This proves the certificate was issued by the CA
    """
    try:
        data = request.get_json()
        
        if not data or 'certificate' not in data:
            return jsonify({
                'status': 'error',
                'message': 'Required: certificate'
            }), 400
        
        cert = data['certificate']
        
        # Check required fields
        required_fields = ['certificate_id', 'subject', 'public_key', 'issued_at', 
                          'expires_at', 'issuer', 'ca_signature']
        if not all(field in cert for field in required_fields):
            return jsonify({
                'status': 'error',
                'message': 'Invalid certificate format'
            }), 400
        
        # Extract signature
        signature = cert['ca_signature']
        
        # Recreate data that was signed
        cert_data = {k: v for k, v in cert.items() if k not in ['ca_signature', 'ca_public_key']}
        data_to_verify = json.dumps(cert_data, sort_keys=True)
        
        # Verify signature
        is_valid = verify_signature(data_to_verify, signature, ca_public_key)
        
        if not is_valid:
            return jsonify({
                'status': 'error',
                'message': 'Certificate signature verification failed',
                'valid': False
            }), 400
        
        # Check expiration
        expires_at = datetime.fromisoformat(cert['expires_at'])
        is_expired = datetime.now() > expires_at
        
        return jsonify({
            'status': 'success',
            'message': 'Certificate verified successfully',
            'valid': True,
            'certificate_id': cert['certificate_id'],
            'subject': cert['subject'],
            'expires_at': cert['expires_at'],
            'expired': is_expired,
            'issued_by': cert['issuer']
        })
    
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Verification error: {str(e)}',
            'valid': False
        }), 500

@app.route('/ca/get-cert', methods=['POST'])
def get_certificate():
    """
    GET CERTIFICATE BY CLIENT ID
    ----------------------------
    Allows clients to retrieve other clients' certificates
    for secure communication
    """
    try:
        data = request.get_json()
        
        if not data or 'client_id' not in data:
            return jsonify({
                'status': 'error',
                'message': 'Required: client_id'
            }), 400
        
        client_id = data['client_id']
        
        print(f"\n🔍 Certificate Lookup Request:")
        print(f"   Looking for: {client_id}")
        print(f"   Registered clients: {[cert['subject'] for cert in certificates_db.values()]}")
        print(f"   Total certificates: {len(certificates_db)}")
        
        # Find certificate for this client
        for cert_id, cert in certificates_db.items():
            if cert['subject'] == client_id:
                print(f"   ✅ FOUND certificate for {client_id}")
                return jsonify({
                    'status': 'success',
                    'certificate': cert
                })
        
        print(f"   ❌ NOT FOUND: {client_id}")
        return jsonify({
            'status': 'error',
            'message': f'No certificate found for client: {client_id}'
        }), 404
    
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Error: {str(e)}'
        }), 500

@app.route('/ca/certificates', methods=['GET'])
def list_certificates():
    """List all issued certificates"""
    certs_list = []
    for cert_id, cert in certificates_db.items():
        certs_list.append({
            'certificate_id': cert_id,
            'subject': cert['subject'],
            'issued_at': cert['issued_at'],
            'expires_at': cert['expires_at']
        })
    
    return jsonify({
        'status': 'success',
        'total_certificates': len(certs_list),
        'certificates': certs_list
    })

@app.route('/ca/reset', methods=['POST'])
def reset_ca():
    """Reset CA database (for testing only)"""
    global certificates_db, client_keys_db
    
    old_cert_count = len(certificates_db)
    old_client_count = len(client_keys_db)
    
    certificates_db.clear()
    client_keys_db.clear()
    
    return jsonify({
        'status': 'success',
        'message': 'CA database reset successfully',
        'cleared_certificates': old_cert_count,
        'cleared_clients': old_client_count
    })

if __name__ == "__main__":
    print("=" * 60)
    print("CERTIFICATE AUTHORITY (CA) SERVER")
    print("=" * 60)
    print("\n🔐 CA Key Pair Information:")
    print(f"   Algorithm: RSA-{ca_public_key.size_in_bits()}")
    print(f"   Signature: SHA256 with PKCS#1 v1.5")
    print("\n📋 Available Endpoints:")
    print("   GET  /              - Server info")
    print("   GET  /ca/info       - Get CA public key")
    print("   POST /ca/register   - Register client & issue certificate")
    print("   POST /ca/verify     - Verify certificate authenticity")
    print("   POST /ca/get-cert   - Get certificate by client_id")
    print("   GET  /ca/certificates - List all certificates")
    print("   POST /ca/reset      - Reset database (testing only)")
    print("="*60)
    print("\n⚠️  IMPORTANT: This server requires localtunnel for access")
    print("\n📝 Setup Instructions:")
    print("   1. Install localtunnel: npm install -g localtunnel")
    print("   2. In a new terminal, run: lt --port 5001 --subdomain ca-server-<yourname>")
    print("   3. Share the generated URL (e.g., https://ca-server-yourname.loca.lt)")
    print("\n✅ CA Server starting on port 5001...")
    print("   Press Ctrl+C to stop\n")
    
    app.run(host='0.0.0.0', port=5001, debug=False)