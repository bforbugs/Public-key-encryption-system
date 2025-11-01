import os
from Crypto.PublicKey import RSA
from OpenSSL import crypto
import warnings
import json
from datetime import datetime
import re
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Define global variable path to rootCAKey folder and rootCACertificate folder
rootCAKey_path = os.path.join(os.path.dirname(__file__), "../keys/rootCA_keys")
rootCACertificate_path = os.path.join(os.path.dirname(__file__), "../certificates/rootCA_certificates")
revoked_cert_file = os.path.join(os.path.dirname(__file__), "../revoked_cert_lists/revoked_certificates.json")
# Suppress deprecation warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

class RootCA:
    def __init__(self):
        self.rootCA_private_key = None  # Class variable to hold the private key
        self.root_cert = None

    def generate_root_ca_key_pair(self):
        # Generate rootCA key pair
        self.rootCA_private_key = RSA.generate(2048)
        rootCA_public_key = self.rootCA_private_key.publickey()
        
        # Save public key to rootKey folder
        with open(os.path.join(rootCAKey_path, "rootCA_public_key.pem"), "wb") as public_key_file:
            public_key_file.write(rootCA_public_key.export_key())

        # Save private key to rootKey folder
        with open(os.path.join(rootCAKey_path, "rootCA_private_key.pem"), "wb") as private_key_file:
            private_key_file.write(self.rootCA_private_key.export_key())
    
    def load_root_ca_key(self):

        # Load private key from root folder
        with open(os.path.join(rootCAKey_path, "rootCA_private_key.pem"), "rb") as private_key_file:
            self.rootCA_private_key = RSA.import_key(private_key_file.read())
    
    def load_root_key_and_cert(self):
        with open(os.path.join(rootCAKey_path, "rootCA_private_key.pem"), "rb") as private_key_file:
            key_data = private_key_file.read()
            self.rootCA_private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_data)

        with open(os.path.join(rootCACertificate_path, "rootCA_cert.pem"), "rb") as root_cert_file:
            cert_data = root_cert_file.read()
            self.root_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)

    def RootCaCert(self):
        # Create a self-signed certificate
        cert = crypto.X509()
        cert.set_version(2)
        basic_constraints = crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE")
        cert.add_extensions([basic_constraints])
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)  # Valid from now
        cert.gmtime_adj_notAfter(31536000)  # Valid for one year
        
        # Set the issuer and subject as the same since this is self-signed
        subject = issuer = crypto.X509Name(cert.get_subject())
        issuer.C = "AU"
        issuer.ST = "Victoria"
        issuer.L = "Monash"
        issuer.O = "Root CA"
        issuer.CN = "rootca.com"
        cert.set_issuer(issuer)
        cert.set_subject(subject)

        # Load the RSA private key
        rsa_key = crypto.load_privatekey(crypto.FILETYPE_PEM, self.rootCA_private_key.export_key())
        cert.set_pubkey(rsa_key)

        # Sign the certificate with the private key
        cert.sign(rsa_key, "sha256")

        # Save the certificate to a file
        with open(os.path.join(rootCACertificate_path, "rootCA_cert.pem"), "wb") as cert_file:
            cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    
    def sign_subca_csr(self, csr, serial_number):
        if not (self.rootCA_private_key and self.root_cert):
            self.load_root_key_and_cert()
        if not (self.rootCA_private_key and self.root_cert):
            print("RootCA private key or certificate is not loaded.")
            return None
        
        # Create a new certificate based on the CSR
        cert = crypto.X509()
        cert.set_serial_number(serial_number)
        cert.set_subject(csr.get_subject())
        cert.set_issuer(self.root_cert.get_subject())  # Set issuer to root CA's subject
        cert.set_pubkey(csr.get_pubkey())
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(31536000)  # Valid for one year
        basic_constraints = crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE")
        cert.add_extensions([basic_constraints])
        # Sign the certificate
        cert.sign(self.rootCA_private_key, 'sha256')
        # Return the PEM-formatted certificate
        return cert
  
    def revoke_list(self, client_cert):
        
        with open(revoked_cert_file, 'r') as file:
            revoked_list = json.load(file)
        try:
            cert_string = crypto.dump_certificate(crypto.FILETYPE_TEXT, client_cert)
            certificate_text_decoded = cert_string.decode('utf-8')
            serial_number_match = re.search(r'Serial Number: (\d+) \(0x[0-9a-f]+\)', certificate_text_decoded)
            if serial_number_match:
                serial_number = serial_number_match.group(1)

                # Check if the serial number is already revoked
                existing_entry = next((item for item in revoked_list['revokedCertificates'] if item['SerialNumber'] == serial_number), None)
                if existing_entry:
                    print(f"This certificate is already revoked on {existing_entry['revocationDate']}.")
                else:
                    # If not revoked, append new entry
                    new_entry = {
                        "SerialNumber": serial_number,
                        "revocationDate": datetime.now().strftime("%Y-%m-%d")
                    }
                    revoked_list['revokedCertificates'].append(new_entry)
                    with open(revoked_cert_file, 'w') as file:
                        json.dump(revoked_list, file, indent=4)
                    print(f"This certificate has been added to the revocation list.")
            else:
                print("Serial Number not found in the certificate.")

        except Exception as e:
            print("Error handling the certificate:", e)   
    
    def validate_client(self, sig, email, message):
        json_file_path = os.path.join(os.path.dirname(__file__), "../data/client_registrations.json")
        
        # Open the JSON file and load its content
        with open(json_file_path, "r") as json_file:
            registrations = json.load(json_file)
        
        if email in registrations:
            print("Email exists in the registrations:", email)
            client_data = registrations[email]
            public_key_pem = client_data["clientPublic_key"]
            
            # Import the public key from PEM format
            public_key = RSA.import_key(public_key_pem)
            # Hash the message using SHA-256
            hash_obj = SHA256.new(message.encode('utf-8'))
            
            # Verify the signature using the public key and the hashed message
            try:
                pkcs1_15.new(public_key).verify(hash_obj, sig)
                print("Signature is valid.")
                return True
            except (ValueError, TypeError):
                print("Signature is not valid.")
                return False
        else:
            print("Email does not exist in the registrations.")
            return False
    
def main():
    # Create an instance of the RootCA class
    root_ca = RootCA()

    if os.path.exists(os.path.join(rootCAKey_path, "rootCA_private_key.pem")):
        if os.path.exists(os.path.join(rootCACertificate_path, "rootCA_cert.pem")):
            print("Keys and Certificate already exist. Exiting program.")
            exit()
        else:
            root_ca.load_root_ca_key()
            root_ca.RootCaCert()
    else:
        root_ca.generate_root_ca_key_pair()
        root_ca.RootCaCert()

if __name__ == "__main__":
    main()