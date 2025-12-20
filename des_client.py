import requests
import json
import os

# Import manual RSA implementation
from rsa_signature import (
    generate_rsa_keypair,
    export_public_key,
    export_private_key,
)

class PKIClientManual:
    def __init__(self, client_id, ca_url, des_server_url):
        self.client_id = client_id
        self.ca_url = ca_url
        self.des_server_url = des_server_url
        self.private_key = None
        self.public_key = None
        self.certificate = None
        self.ca_public_key = None
        self.key_file = f"{client_id}_manual_private_key.json"
        self.cert_file = f"{client_id}_manual_certificate.json"
        
    def save_keys_and_cert(self):
        """Save private key and certificate to files"""
        try:
            # Save private key
            with open(self.key_file, 'w') as f:
                json.dump(self.private_key, f, indent=2, default=str)
            
            # Save certificate
            with open(self.cert_file, 'w') as f:
                json.dump(self.certificate, f, indent=2)
            
            print(f"💾 Keys and certificate saved to:")
            print(f"   - {self.key_file}")
            print(f"   - {self.cert_file}")
        except Exception as e:
            print(f"⚠️  Warning: Could not save keys: {e}")
    
    def load_keys_and_cert(self):
        try:
            if os.path.exists(self.key_file) and os.path.exists(self.cert_file):
                # Load private key
                with open(self.key_file, 'r') as f:
                    key_data = json.load(f)
                    self.private_key = {
                        'n': int(key_data['n']),
                        'd': int(key_data['d']),
                        'p': int(key_data['p']),
                        'q': int(key_data['q'])
                    }
                self.public_key = {
                    'n': self.private_key['n'],
                    'e': 65537
                }
                
                # Load certificate
                with open(self.cert_file, 'r') as f:
                    self.certificate = json.load(f)
                
                print(f"✅ Loaded existing keys and certificate from disk")
                print(f"   Subject: {self.certificate['subject']}")
                print(f"   Certificate ID: {self.certificate['certificate_id']}")
                return True
        except Exception as e:
            print(f"⚠️  Could not load existing keys: {e}")
        
        return False
        
    def generate_keys(self):
        print(f"\n🔐 Generating NEW RSA key pair for {self.client_id}...")
        print("   Using MANUAL RSA implementation (no external crypto library)")
        
        keypair = generate_rsa_keypair(bits=1024)
        self.private_key = keypair['private_key']
        self.public_key = keypair['public_key']
        
        print("✅ Keys generated successfully!")
        print(f"   Key size: {self.public_key['n'].bit_length()} bits")
        
    def register_with_ca(self, force_new=False):
        """Register with CA and get digital certificate"""
        
        # Try to load existing keys first
        if not force_new and self.load_keys_and_cert():
            # Get CA public key
            response = requests.get(f"{self.ca_url}/ca/info")
            if response.status_code == 200:
                self.ca_public_key = response.json()['ca_public_key']
                print("✅ Using existing registration")
                return True
        
        # Generate new keys if needed
        if not self.public_key:
            self.generate_keys()
        
        print(f"\n📝 Registering with Certificate Authority (Manual RSA)...")
        
        # Get CA public key first
        response = requests.get(f"{self.ca_url}/ca/info")
        if response.status_code == 200:
            self.ca_public_key = response.json()['ca_public_key']
            print("   ✅ CA public key retrieved")
        else:
            print("❌ Failed to get CA public key")
            return False
        
        # Register and get certificate
        public_key_json = export_public_key(self.public_key)
        
        data = {
            'client_id': self.client_id,
            'public_key': public_key_json
        }
        
        response = requests.post(f"{self.ca_url}/ca/register", json=data)
        
        if response.status_code == 200:
            result = response.json()
            self.certificate = result['certificate']
            print(f"✅ Certificate issued successfully!")
            print(f"   Certificate ID: {result['certificate_id']}")
            print(f"   Valid until: {self.certificate['expires_at']}")
            print(f"   Signature: Manual RSA-SHA256")
            
            # Save to disk for future use
            self.save_keys_and_cert()
            return True
        else:
            print(f"❌ Registration failed: {response.json().get('message', 'Unknown error')}")
            return False
    
    def get_receiver_certificate(self, receiver_id):
        """Get receiver's certificate from CA"""
        print(f"\n🔍 Fetching certificate for {receiver_id}...")
        
        response = requests.post(
            f"{self.ca_url}/ca/get-cert",
            json={'client_id': receiver_id}
        )
        
        if response.status_code == 200:
            cert = response.json()['certificate']
            print(f"✅ Certificate retrieved for {receiver_id}")
            return cert
        else:
            print(f"❌ Certificate not found for {receiver_id}")
            return None
    
    def send_secure_message(self, receiver_id, message):
        """Send encrypted AND SIGNED message using Manual RSA"""
        print(f"\n📤 Sending secure message to {receiver_id}...")
        print("   Using Manual RSA for encryption and signature")
        
        # Get receiver's certificate
        receiver_cert = self.get_receiver_certificate(receiver_id)
        if not receiver_cert:
            return False, "Receiver certificate not found"
        
        # Prepare request with sender's private key for signing
        data = {
            'text': message,
            'sender_certificate': self.certificate,
            'receiver_certificate': receiver_cert,
            'ca_public_key': self.ca_public_key,
            'sender_private_key': export_private_key(self.private_key)
        }
        
        response = requests.post(
            f"{self.des_server_url}/send-secure",
            json=data
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Message encrypted and SIGNED successfully!")
            return True, result
        else:
            error_msg = response.json().get('message', 'Unknown error')
            print(f"❌ Failed: {error_msg}")
            return False, error_msg
    
    def receive_secure_message(self, message_id):
        """Receive, decrypt, and VERIFY message signature"""
        print(f"\n📥 Receiving secure message {message_id}...")
        print("   Using Manual RSA for decryption and verification")
        
        data = {
            'message_id': message_id,
            'private_key': export_private_key(self.private_key),
            'certificate': self.certificate,
            'ca_public_key': self.ca_public_key
        }
        
        response = requests.post(
            f"{self.des_server_url}/receive-secure",
            json=data
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Message decrypted and verified!")
            return True, result
        else:
            error_msg = response.json().get('message', 'Unknown error')
            print(f"❌ Failed: {error_msg}")
            return False, error_msg

    def sign_document(self, document):
        """Sign a document WITHOUT encryption (Manual RSA)"""
        print(f"\n✍️  Signing document (Manual RSA-SHA256)...")
        
        data = {
            'message': document,
            'private_key': export_private_key(self.private_key),
            'certificate': self.certificate,
            'ca_public_key': self.ca_public_key
        }
        
        response = requests.post(
            f"{self.des_server_url}/sign",
            json=data
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Document signed successfully!")
            return True, result
        else:
            error_msg = response.json().get('message', 'Unknown error')
            print(f"❌ Failed: {error_msg}")
            return False, error_msg
    
    def verify_document_signature(self, document, signature, signer_id):
        """Verify a document's signature (Manual RSA)"""
        print(f"\n🔍 Verifying signature from {signer_id}...")
        
        # Get signer's certificate
        signer_cert = self.get_receiver_certificate(signer_id)
        if not signer_cert:
            return False, "Signer certificate not found"
        
        data = {
            'message': document,
            'signature': signature,
            'certificate': signer_cert,
            'ca_public_key': self.ca_public_key
        }
        
        response = requests.post(
            f"{self.des_server_url}/verify-signature",
            json=data
        )
        
        if response.status_code == 200:
            result = response.json()
            return True, result
        else:
            error_msg = response.json().get('message', 'Unknown error')
            print(f"❌ Failed: {error_msg}")
            return False, error_msg

def main():
    """Main client interface"""
    print("=" * 60)
    print("   PKI-ENABLED SECURE MESSAGING CLIENT")
    print("   MANUAL RSA IMPLEMENTATION")
    print("   (No external crypto library)")
    print("=" * 60)
    
    # Initialize client
    print("\n🔧 CLIENT SETUP")
    print("⚠️  Make sure CA and DES servers are running")
    print("    (Use certificate_server_manual.py and des_server_manual.py)\n")
    
    client_id = input("Enter your client ID: ").strip()
    ca_url = input("CA Server URL (e.g., http://localhost:5001): ").strip()
    des_server_url = input("DES Server URL (e.g., http://localhost:5002): ").strip()
    
    if not ca_url or not des_server_url:
        print("\n❌ Error: Server URLs are required!")
        return
    
    client = PKIClientManual(client_id, ca_url, des_server_url)
    
    # Register with CA
    if not client.register_with_ca():
        print("\n❌ Failed to register with CA. Exiting...")
        return
    
    # Main menu
    while True:
        print("\n" + "=" * 60)
        print("MENU (Manual RSA Implementation):")
        print("  1. Send Secure Message (Encrypted + Signed)")
        print("  2. Receive Secure Message (Decrypt + Verify)")
        print("  3. Sign Document (No Encryption)")
        print("  4. Verify Document Signature")
        print("  5. View My Certificate")
        print("  6. Re-register (Generate New Keys)")
        print("  7. Exit")
        print("=" * 60)
        
        choice = input("\nChoose option (1-7): ").strip()
        
        if choice == '1':
            # SEND MESSAGE
            print("\n=== SEND SECURE MESSAGE ===")
            receiver_id = input("Receiver's Client ID: ").strip()
            message = input("Your message: ").strip()
            
            success, result = client.send_secure_message(receiver_id, message)
            
            if success:
                print(f"\n✅ SUCCESS!")
                print(f"Message ID: {result['message_id']}")
                print(f"Receiver: {result['receiver']}")
                print(f"\n🔐 Security Info (Manual RSA):")
                print(f"   - Message encrypted with DES")
                print(f"   - Session key encrypted with Manual RSA")
                print(f"   - Message SIGNED with Manual RSA-SHA256")
                print(f"   - Identity verified via CA certificate")
                print(f"\nShare this Message ID with {receiver_id}: {result['message_id']}")
        
        elif choice == '2':
            # RECEIVE MESSAGE
            print("\n=== RECEIVE SECURE MESSAGE ===")
            message_id = input("Message ID: ").strip()
            
            success, result = client.receive_secure_message(message_id)
            
            if success:
                print(f"\n✅ SUCCESS!")
                print(f"From: {result['sender']}")
                print(f"Message: {result['plaintext']}")
                print(f"Sent: {result['timestamp']}")
                print(f"\n🔐 Security Info (Manual RSA):")
                print(f"   - Session key decrypted with Manual RSA")
                print(f"   - Message decrypted with DES")
                print(f"   - Sender verified via CA certificate")
                if 'signature_verification' in result:
                    sig_info = result['signature_verification']
                    print(f"   - Signature: {sig_info['status']}")
                    if sig_info['valid']:
                        print(f"   - Non-repudiation: Sender cannot deny this message")
        
        elif choice == '3':
            # SIGN DOCUMENT
            print("\n=== SIGN DOCUMENT (Manual RSA-SHA256) ===")
            document = input("Enter document/message to sign: ").strip()
            
            success, result = client.sign_document(document)
            
            if success:
                print(f"\n✅ DOCUMENT SIGNED (Manual RSA)!")
                print(f"Signer: {result['signer']}")
                print(f"Algorithm: {result['algorithm']}")
                print(f"Timestamp: {result['timestamp']}")
                print(f"\n📋 Signature (share this with verifier):")
                print(result['signature'])
                print(f"\n💾 Full signature length: {len(result['signature'])} characters")
                print(f"\n📝 To verify, the receiver needs:")
                print(f"   1. The original document")
                print(f"   2. This signature")
                print(f"   3. Your client ID: {client.client_id}")
        
        elif choice == '4':
            # VERIFY SIGNATURE
            print("\n=== VERIFY DOCUMENT SIGNATURE ===")
            document = input("Enter the original document: ").strip()
            signature = input("Enter the signature: ").strip()
            signer_id = input("Signer's Client ID: ").strip()
            
            # TAMPERING OPTION
            print("\n⚠️  TAMPERING TEST (Optional)")
            print("Do you want to tamper with the document before verification?")
            print("  1. No - Verify as is")
            print("  2. Yes - Tamper with document (to test signature detection)")
            
            tamper_choice = input("\nChoose (1-2): ").strip()
            
            if tamper_choice == '2':
                print("\n🔧 TAMPERING OPTIONS:")
                print("  1. Add text to end")
                print("  2. Change one character")
                print("  3. Add/remove space")
                print("  4. Change case of a character")
                print("  5. Replace a word")
                print("  6. Custom modification")
                
                method = input("\nChoose tampering method (1-6): ").strip()
                original_doc = document
                
                if method == '1':
                    tamper_text = input("Text to add: ").strip()
                    document = document + tamper_text
                    print(f"   Modified: Added '{tamper_text}' to end")
                
                elif method == '2':
                    if len(document) > 0:
                        try:
                            idx = int(input(f"Character position to change (0-{len(document)-1}): "))
                            if 0 <= idx < len(document):
                                new_char = input(f"Replace '{document[idx]}' with: ").strip()
                                if new_char:
                                    document = document[:idx] + new_char[0] + document[idx+1:]
                                    print(f"   Modified: Changed position {idx} from '{original_doc[idx]}' to '{new_char[0]}'")
                        except ValueError:
                            print("   Invalid position, no changes made")
                
                elif method == '3':
                    space_choice = input("Add or remove space? (add/remove): ").strip().lower()
                    if space_choice == 'add':
                        try:
                            idx = int(input(f"Position to add space (0-{len(document)}): "))
                            document = document[:idx] + " " + document[idx:]
                            print(f"   Modified: Added space at position {idx}")
                        except ValueError:
                            print("   Invalid position, no changes made")
                    elif space_choice == 'remove':
                        document = document.replace(" ", "", 1)
                        print(f"   Modified: Removed first space")
                
                elif method == '4':
                    if len(document) > 0:
                        try:
                            idx = int(input(f"Position to change case (0-{len(document)-1}): "))
                            if 0 <= idx < len(document):
                                if document[idx].islower():
                                    document = document[:idx] + document[idx].upper() + document[idx+1:]
                                    print(f"   Modified: Changed '{original_doc[idx]}' to uppercase")
                                elif document[idx].isupper():
                                    document = document[:idx] + document[idx].lower() + document[idx+1:]
                                    print(f"   Modified: Changed '{original_doc[idx]}' to lowercase")
                                else:
                                    print(f"   Character at position {idx} is not a letter")
                        except ValueError:
                            print("   Invalid position, no changes made")
                
                elif method == '5':
                    old_word = input("Word to replace: ").strip()
                    new_word = input("Replace with: ").strip()
                    if old_word in document:
                        document = document.replace(old_word, new_word, 1)
                        print(f"   Modified: Replaced '{old_word}' with '{new_word}'")
                    else:
                        print(f"   Word '{old_word}' not found in document")
                
                elif method == '6':
                    print(f"\nOriginal: {original_doc}")
                    document = input("Enter modified document: ").strip()
                    print(f"   Modified to: {document}")
                
                print(f"\n📝 Original document: {original_doc}")
                print(f"🔧 Tampered document: {document}")
                print(f"⚠️  Signature verification should FAIL if document was modified!")
            
            success, result = client.verify_document_signature(document, signature, signer_id)
            
            if success:
                if result['signature_valid']:
                    print(f"\n✅ SIGNATURE VERIFIED (Manual RSA)!")
                    print(f"   - Signer: {result['signer']}")
                    print(f"   - Algorithm: Manual RSA-SHA256")
                    print(f"   - The document is authentic and unmodified")
                    print(f"   - Non-repudiation: {result['signer']} cannot deny signing this")
                else:
                    print(f"\n❌ SIGNATURE INVALID!")
                    print(f"   - The document may have been tampered with")
                    print(f"   - Or the signature doesn't match the signer")
                    if tamper_choice == '2':
                        print(f"\n✓ Tampering detected successfully!")
                        print(f"   The signature verification correctly identified the modification.")
        
        elif choice == '5':
            # VIEW CERTIFICATE
            print("\n=== YOUR CERTIFICATE ===")
            if client.certificate:
                print(f"Certificate ID: {client.certificate['certificate_id']}")
                print(f"Subject: {client.certificate['subject']}")
                print(f"Issued: {client.certificate['issued_at']}")
                print(f"Expires: {client.certificate['expires_at']}")
                print(f"Issuer: {client.certificate['issuer']}")
                print(f"\nPublic Key (n): {str(client.public_key['n'])[:50]}...")
                print(f"Public Exponent (e): {client.public_key['e']}")
            else:
                print("No certificate available")
        
        elif choice == '6':
            # RE-REGISTER
            print("\n⚠️  WARNING: This will generate NEW keys and invalidate old messages!")
            confirm = input("Are you sure? (yes/no): ").strip().lower()
            if confirm == 'yes':
                # Delete old key files
                if os.path.exists(client.key_file):
                    os.remove(client.key_file)
                if os.path.exists(client.cert_file):
                    os.remove(client.cert_file)
                
                client.private_key = None
                client.public_key = None
                
                if client.register_with_ca(force_new=True):
                    print("✅ Re-registered successfully with new keys!")
                else:
                    print("❌ Re-registration failed!")
        
        elif choice == '7':
            print("\n👋 Goodbye!")
            break
        else:
            print("\n❌ Invalid choice!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Program interrupted. Goodbye!")
