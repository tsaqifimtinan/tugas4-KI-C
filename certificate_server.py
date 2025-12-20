from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import uuid
from datetime import datetime, timedelta

# Import manual RSA implementation
from rsa_signature import (
    generate_rsa_keypair,
    export_public_key,
    sign_certificate_data,
    verify_certificate_signature,
)

app = Flask(__name__)
CORS(app)

# ========================================
# CA KEY PAIR GENERATION
# ========================================
print("="*60)
print("Generating Certificate Authority (CA) key pair...")
print("Using MANUAL RSA implementation (no external crypto library)")
print("="*60)

ca_keypair = generate_rsa_keypair(bits=1024)  # 1024-bit for reasonable speed
ca_private_key = ca_keypair['private_key']
ca_public_key = ca_keypair['public_key']

print("✅ CA keys generated successfully!")
print(f"   Key size: {ca_public_key['n'].bit_length()} bits")
print(f"   Public exponent (e): {ca_public_key['e']}")

# Certificate storage: {cert_id: certificate_data}
certificates_db = {}
# Client public keys: {client_id: public_key_json}
client_keys_db = {}

# ========================================
# HELPER FUNCTIONS
# ========================================

def create_certificate(client_id, client_public_key_json, validity_days=365):
    """
    Create a digital certificate for a client
    """
    cert_id = str(uuid.uuid4())[:12]
    issued_at = datetime.now()
    expires_at = issued_at + timedelta(days=validity_days)
    
    # Certificate data to be signed
    cert_data = {
        'certificate_id': cert_id,
        'subject': client_id,
        'public_key': client_public_key_json,
        'issued_at': issued_at.isoformat(),
        'expires_at': expires_at.isoformat(),
        'issuer': 'Manual RSA Certificate Authority'
    }
    
    # Create signature over certificate data (using manual RSA)
    signature = sign_certificate_data(cert_data, ca_private_key)
    
    # Complete certificate with signature
    certificate = {
        **cert_data,
        'ca_signature': signature,
        'ca_public_key': export_public_key(ca_public_key)
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
        'implementation': 'MANUAL RSA - No external crypto library',
        'description': 'Issues and verifies digital certificates for secure key distribution',
        'security': {
            'key_generation': 'Manual RSA with Miller-Rabin primality test',
            'hashing': 'Manual SHA-256 implementation',
            'signatures': 'RSA-SHA256 with PKCS#1 v1.5 padding'
        },
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
    """
    return jsonify({
        'status': 'success',
        'ca_public_key': export_public_key(ca_public_key),
        'key_size': ca_public_key['n'].bit_length(),
        'algorithm': 'Manual RSA with SHA-256 signatures',
        'implementation': 'No external crypto library used'
    })

@app.route('/ca/register', methods=['POST'])
def register_client():
    """
    CLIENT REGISTRATION
    """
    try:
        data = request.get_json()
        
        if not data or 'client_id' not in data or 'public_key' not in data:
            return jsonify({
                'status': 'error',
                'message': 'Required: client_id, public_key'
            }), 400
        
        client_id = data['client_id']
        client_public_key_json = data['public_key']
        
        # Validate public key format (should be JSON with n and e)
        try:
            key_data = json.loads(client_public_key_json) if isinstance(client_public_key_json, str) else client_public_key_json
            if 'n' not in key_data or 'e' not in key_data:
                raise ValueError("Missing n or e")
        except:
            return jsonify({
                'status': 'error',
                'message': 'Invalid public key format. Expected JSON with n and e fields.'
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
        
        # Create certificate (with manual RSA signature)
        cert_id, certificate = create_certificate(client_id, client_public_key_json)
        
        # Store certificate and public key
        certificates_db[cert_id] = certificate
        client_keys_db[client_id] = client_public_key_json
        
        print(f"\n📜 Certificate issued for '{client_id}'")
        print(f"   Certificate ID: {cert_id}")
        print(f"   Signed with: Manual RSA-SHA256")
        
        return jsonify({
            'status': 'success',
            'message': 'Certificate issued successfully (Manual RSA signature)',
            'certificate_id': cert_id,
            'certificate': certificate,
            'security_info': {
                'signature_algorithm': 'Manual RSA-SHA256',
                'no_external_crypto': True
            },
            'instruction': 'Save this certificate. You will need it for secure communication.'
        })
    
    except Exception as e:
        import traceback
        return jsonify({
            'status': 'error',
            'message': f'Registration error: {str(e)}',
            'traceback': traceback.format_exc()
        }), 500

@app.route('/ca/verify', methods=['POST'])
def verify_certificate():
    """
    CERTIFICATE VERIFICATION
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
        
        # Verify signature (using manual RSA)
        is_valid = verify_certificate_signature(cert, ca_public_key)
        
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
            'message': 'Certificate verified successfully (Manual RSA)',
            'valid': True,
            'certificate_id': cert['certificate_id'],
            'subject': cert['subject'],
            'expires_at': cert['expires_at'],
            'expired': is_expired,
            'issued_by': cert['issuer'],
            'verification_method': 'Manual RSA-SHA256'
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
        'certificates': certs_list,
        'signature_algorithm': 'Manual RSA-SHA256'
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
    print("\n" + "=" * 60)
    print("CERTIFICATE AUTHORITY (CA) SERVER")
    print("MANUAL RSA IMPLEMENTATION - No External Crypto Library")
    print("=" * 60)
    print("\n🔐 CA Key Pair Information:")
    print(f"   Algorithm: Manual RSA-{ca_public_key['n'].bit_length()}")
    print(f"   Signature: Manual SHA-256 + RSA PKCS#1 v1.5")
    print(f"   Key Generation: Miller-Rabin primality test")
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
