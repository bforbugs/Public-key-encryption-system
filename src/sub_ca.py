import os
from Crypto.PublicKey import RSA
from OpenSSL import crypto
import base64
from Crypto.Cipher import PKCS1_OAEP, AES
import hashlib
from root_ca import RootCA


# Define global variable path to subCAKey folder and subCACertificate folder
subCAKey_path = os.path.join(os.path.dirname(__file__), "../keys/subCA_keys")
subCACertificate_path = os.path.join(os.path.dirname(__file__), "../certificates/subCA_certificates")
rootCAKey_path = os.path.join(os.path.dirname(__file__), "../keys/rootCA_keys")
rootCACertificate_path = os.path.join(os.path.dirname(__file__), "../certificates/rootCA_certificates")
revoked_cert_file = os.path.join(os.path.dirname(__file__), "../revoked_cert_lists/revoked_certificates.json")

class SubCa():
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.subCAC = None

    def generate_subCa_key(self):
        # Generate key pair
        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.publickey()
        
        return self.private_key
    
    def load_cert_public(self):
        # Load private key from subCAKey folder
        with open(os.path.join(subCACertificate_path, "subca1_cert.pem"), "rb") as cert_file:
            self.subCAC = RSA.import_key(cert_file.read())
        
        return self.subCAC
    
    def load_key_pair(self):

         # Load public key from subCAKey folder
        with open(os.path.join(rootCAKey_path, "subca_public_key.pem"), "rb") as public_key_file:
            self.public_key = RSA.import_key(public_key_file.read())

        # Load private key from subCAKey folder
        with open(os.path.join(rootCAKey_path, "subca_private_key.pem"), "rb") as private_key_file:
            self.private_key = RSA.import_key(private_key_file.read())

    def create_csr_for_subCA(self, key):
        req = crypto.X509Req()
        # Define subject information for the CSR
        subjects = {
            'C': 'US',
            'ST': 'California',
            'L': 'San Francisco',
            'O': 'Sub CA Ltd',
            'OU': 'Certificates',
            'CN': 'subca.example.com'
        }
        subj = req.get_subject()
        for field, value in subjects.items():
            setattr(subj, field, value)
        
        pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, key.export_key())
        
        req.set_pubkey(pkey)
        req.sign(pkey, "sha256")
        return req
    
    def sign_client_csr(self, encrypted_aes_key_base64, encrypted_csr_base64, id):
        sub_ca_private_key = f"subca{id}_private_key.pem"
        sub_ca_cert_key = f"subca{id}_cert.pem"

        subCAKey_path = os.path.join(os.path.dirname(__file__), "../keys/subCA_keys", f"subca{id}")
        subCACertificate_path = os.path.join(os.path.dirname(__file__), "../certificates/subCA_certificates", f"subca{id}")
        
        with open(os.path.join(subCAKey_path, sub_ca_private_key), "rb") as private_key_file:
            self.private_key = RSA.import_key(private_key_file.read())
        # Load SubCA certificate
        with open(os.path.join(subCACertificate_path, sub_ca_cert_key), "rb") as subCA_file:
            subCA_cert_data = subCA_file.read()
            self.subCAC = crypto.load_certificate(crypto.FILETYPE_PEM, subCA_cert_data)

        encrypted_aes_key = base64.b64decode(encrypted_aes_key_base64)
        encrypted_data = base64.b64decode(encrypted_csr_base64)

        # Decrypt the AES key
        rsa_cipher = PKCS1_OAEP.new(self.private_key)
        aes_key = rsa_cipher.decrypt(encrypted_aes_key)

        # Decrypt the data using AES
        nonce = encrypted_data[:16]
        tag = encrypted_data[16:32]
        encrypted_csr = encrypted_data[32:]
        aes_cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        csr = aes_cipher.decrypt_and_verify(encrypted_csr, tag).decode('utf-8')

        csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr)
        
        subject = csr.get_subject()
        email = subject.emailAddress
        hash_object = hashlib.sha256(email.encode())
        hex_dig = hash_object.hexdigest()
        # Take the first 6 characters of the hash and convert to a base 10 integer
        hex_dig = hex_dig.ljust(6, '0')
        serialNumber = int(hex_dig[:6], 16) 
        unPs_aerial = serialNumber % 1000000
        serialNumber =  int(f"{unPs_aerial:06d}")
        # Create a new certificate based on the CSR
        cert = crypto.X509()
        cert.set_serial_number(serialNumber)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(3 * 3 * 24 * 60 * 60)
        cert.set_issuer(self.subCAC.get_subject())
        cert.set_subject(csr.get_subject())
        cert.set_pubkey(csr.get_pubkey())
        
        with open(os.path.join(subCAKey_path, sub_ca_private_key), "rb") as private_key_file:
            self.private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, private_key_file.read())
        # Sign the certificate with the Sub CA's private key
        cert.sign(self.private_key, 'sha256')
        return cert

    def check_existing_subcas(self):
        return sum(os.path.isdir(os.path.join(subCAKey_path, item)) for item in os.listdir(subCAKey_path))

def main():
        
        # Instantiate the SubCa class
        sub_ca = SubCa()
        root_ca = RootCA()

        # Check if any subCA files exist
        existing_subcas = sub_ca.check_existing_subcas()
        if existing_subcas:
            print(f"{existing_subcas} Subordinate CA already generated.")
            additional = input("Do you want to generate additional subordinate CAs? (yes/no): ")
            if additional.lower() == "yes":
                # Calculate the number of existing subcas
                num_existing_subcas = existing_subcas
                num_subcas = int(input(f"Enter the number of additional subordinate CAs to generate starting from subca{num_existing_subcas}: "))
                for i in range(num_existing_subcas, num_existing_subcas + num_subcas):
                    # Generate the subordinate CA's key pair
                    sub_ca_private_key = sub_ca.generate_subCa_key()
                    # Create a CSR for the subordinate CA-
                    csr = sub_ca.create_csr_for_subCA(sub_ca_private_key)
                    # Sign the CSR to generate a subordinate CA certificate
                    # sub_ca_cert = sub_ca.sign_csr(csr, root_ca_cert, root_ca_private_key, serial_number=10000 + i, valid_days=365)
                    sub_ca_cert = root_ca.sign_subca_csr(csr, serial_number=10000+i)
                    # Save the private key to a file
                    subCAKey_path = os.path.join(os.path.dirname(__file__), "../keys/subCA_keys", f"subca{i+1}")
                    if not os.path.exists(subCAKey_path):
                        os.makedirs(subCAKey_path)
                    with open(os.path.join(subCAKey_path, f"subca{i+1}_private_key.pem"), "wb") as private_key_file:
                        private_key_file.write(sub_ca_private_key.export_key())
                    # Save the public key to a file
                    with open(os.path.join(subCAKey_path, f"subca{i+1}_public_key.pem"), "wb") as public_key_file:
                        public_key_file.write(sub_ca.public_key.export_key())
                    # Save the certificate to a file
                    subCACertificate_path = os.path.join(os.path.dirname(__file__), "../certificates/subCA_certificates", f"subca{i+1}")
                    if not os.path.exists(subCACertificate_path):
                        os.makedirs(subCACertificate_path)
                    with open(os.path.join(subCACertificate_path, f"subca{i+1}_cert.pem"), "wb") as cert_file:
                        cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, sub_ca_cert))
                    print(f"SubCA {i+1} has been generated.")
        else:
            num_subcas = int(input("Enter the number of subordinate CAs to generate: "))
            for i in range(num_subcas):
                # Generate the subordinate CA's key pair
                sub_ca_private_key = sub_ca.generate_subCa_key()
                # Create a CSR for the subordinate CA
                csr = sub_ca.create_csr_for_subCA(sub_ca_private_key)
                # Sign the CSR to generate a subordinate CA certificate
                sub_ca_cert = root_ca.sign_subca_csr(csr, serial_number=10000+i)
                # Save the private key to a file
                subCAKey_path = os.path.join(os.path.dirname(__file__), "../keys/subCA_keys", f"subca{i+1}")
                if not os.path.exists(subCAKey_path):
                    os.makedirs(subCAKey_path)
                with open(os.path.join(subCAKey_path, f"subca{i+1}_private_key.pem"), "wb") as private_key_file:
                    private_key_file.write(sub_ca_private_key.export_key())
                # Save the public key to a file
                with open(os.path.join(subCAKey_path, f"subca{i+1}_public_key.pem"), "wb") as public_key_file:
                    public_key_file.write(sub_ca.public_key.export_key())
                # Save the certificate to a file
                subCACertificate_path = os.path.join(os.path.dirname(__file__), "../certificates/subCA_certificates", f"subca{i+1}")
                if not os.path.exists(subCACertificate_path):
                    os.makedirs(subCACertificate_path)
                with open(os.path.join(subCACertificate_path, f"subca{i+1}_cert.pem"), "wb") as cert_file:
                    cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, sub_ca_cert))
                print(f"SubCA {i+1} has been generated.")  
                   
if __name__ == "__main__":
    main()