# Importing necessary modules
from Crypto.PublicKey import RSA  
from Crypto.Cipher import PKCS1_OAEP, AES  
from Crypto.Random import get_random_bytes  
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256  
from asn1crypto import pem, x509  
from OpenSSL import crypto  
import uuid, sys, os, base64, json, secrets, string
import hashlib, datetime


# Import sub_ca module
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.join(os.path.dirname(current_dir))
sys.path.append(parent_dir)
from sub_ca import SubCa
from root_ca import RootCA

# Constructing file paths for client.py
client_private_key_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "client_private_key.pem")
client_registrations_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "client_registrations.json")
client_cert_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "client_cert.pem")
client_registration_database_path = os.path.join(os.path.dirname(current_dir), f"../data")
subCA_directory_path = os.path.join(os.path.dirname(current_dir), "../keys/subCA_keys/")
revoked_cert_file = os.path.join(os.path.dirname(__file__), "../../revoked_cert_lists/revoked_certificates.json")


class ClientRegistration():
    def __init__(self):
        # Initializing instance variables
        self.private_key = None
        self.public_key = None
        self.clientID = None
        self.country = None
        self.state = None
        self.city = None
        self.clientName = None
        self.email = None

    def generate_key_pair(self):
        # Generate RSA key pair and export private key
        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.publickey()
        # Write the private key to the client private key path
        with open(client_private_key_path, "wb") as private_key_file:
            private_key_file.write(self.private_key.export_key())

    def client_register(self):
        # Check if required files exist, load existing registrations if available
        required_files = [
            os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client_private_key.pem'),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client_cert.pem')]
        missing_files = [file for file in required_files if not os.path.isfile(file)]
        if missing_files:
            # Check if the JSON file for client registrations exists
            client_registration_database_path = os.path.join(os.path.dirname(current_dir), "../data/client_registrations.json")
            if os.path.isfile(client_registration_database_path):
                # Load existing client registrations from JSON file
                with open(client_registration_database_path, 'r') as f:
                    registrations = json.load(f)
            else:
                # Create an empty dictionary for registrations if the file doesn't exist
                registrations = {}

            # Register the client by taking necessary details from user input
            self.clientName = input("Enter client name: ")
            self.email = input("Enter client email: ")
            self.country = input("Enter client country: ")
            self.state = input("Enter client state: ")
            self.city = input("Enter client locality: ")

            # Check if client email already exists in registrations
            if self.email in registrations:
                print("Warning: Client with this email already registered.")
                return None

            # Generate a unique client ID
            self.generate_key_pair()
            self.clientID = str(uuid.uuid4())
            
            hash_object = hashlib.sha256(self.email.encode())
            hex_dig = hash_object.hexdigest()
            # Take the first 6 characters of the hash and convert to a base 10 integer
            hex_dig = hex_dig.ljust(6, '0')
            serialNumber = int(hex_dig[:6], 16) 
            unPs_aerial = serialNumber % 1000000
            self.serialNumber =  int(f"{unPs_aerial:06d}")
        
            public_key_pem = self.public_key.export_key().decode('utf-8')
            
            # Update or create client registration info in registrations dictionary
            registrations[self.email] = {
                "clientEmail": self.email,
                "clientID": self.clientID,
                "clientPublic_key": public_key_pem
            }

            # Write updated registrations to the JSON file
            with open(client_registration_database_path, 'w') as f:
                json.dump(registrations, f)
            print(f"Client {self.clientName} registered successfully with ID {self.clientID}.")
        else:
            return False

    def create_csr_for_client(self):
        req = crypto.X509Req()
        # Directly set subject attributes in the CSR
        req.get_subject().CN = self.clientName
        req.get_subject().countryName = self.country
        req.get_subject().stateOrProvinceName = self.state
        req.get_subject().localityName = self.city
        req.get_subject().emailAddress = self.email
        
        # Convert the RSA public key to a PEM format string
        private_key_pem = self.private_key.export_key(format='PEM')
        # Load the RSA private key into a PKey object
        pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, private_key_pem)
        # Set the public key in the CSR
        req.set_pubkey(pkey)
        req.sign(pkey, 'sha256')
        csr_pem = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)

        # List all files in the directory
        all_files = os.listdir(subCA_directory_path)

        # Count the occurrences of files with the name 'public_key.pem'
        number_subca = sum(1 for file in all_files if file.endswith('public_key.pem'))
        
        number_subca = sum(os.path.isdir(os.path.join(subCA_directory_path, item)) for item in os.listdir(subCA_directory_path))
        # Generate choices based on the number of sub CAs
        choices = ", ".join([f"subca {i}" for i in range(1, number_subca + 1)])

        # Print the available subCAs
        print(f"Available subCAs: {choices}")
        
        # Input the chosen subCA
        chosen_subca = int(input("Chosen sub_ca: "))
        subcaKey_path = os.path.join(os.path.dirname(current_dir), f"../keys/subCA_keys/subca{chosen_subca}/subca{chosen_subca}_public_key.pem")
        
     
        try:
            with open(subcaKey_path, 'rb') as file:
                public_key_pem = file.read()
        except IOError as e:
            print("File error: ", e)
            return None
            
        public_key = RSA.import_key(public_key_pem)
        # Create RSA cipher object using the public key
        rsa_cipher = PKCS1_OAEP.new(public_key)
        # Generate a random symmetric key for AES
        aes_key = get_random_bytes(16)

        # Encrypt the AES key using RSA
        encrypted_aes_key = rsa_cipher.encrypt(aes_key)
        # Encrypt the CSR using AES
        aes_cipher = AES.new(aes_key, AES.MODE_EAX)
        nonce = aes_cipher.nonce
        encrypted_csr, tag = aes_cipher.encrypt_and_digest(csr_pem)

        # Combine the encrypted data with the nonce and the tag
        encrypted_data = nonce + tag + encrypted_csr
        encrypted_aes_key_base64 = base64.b64encode(encrypted_aes_key).decode('utf-8')
        encrypted_data_base64 = base64.b64encode(encrypted_data).decode('utf-8')

        return encrypted_aes_key_base64, encrypted_data_base64, chosen_subca

    
    def verify_date(self, client_cert_path):
        current_time = datetime.datetime.now(datetime.timezone.utc)
        with open(client_cert_path, 'rb') as cert_file:
            cert_data = cert_file.read()
            if pem.detect(cert_data):
                _, _, der_data = pem.unarmor(cert_data)
                cert = x509.Certificate.load(der_data)
                # start_date = cert["tbs_certificate"]["validity"]["not_before"].native
                end_date = cert["tbs_certificate"]["validity"]["not_after"].native

                if end_date <= current_time:
                    # print("Certificate is expired.")
                    return False
                # if current_time < start_date:
                #     # print("Certificate is not yet valid.")
                #     return False
                # print("Certificate is valid.")
                return True
            else:
                # print("Invalid certificate format.")
                return False

    def verify_signature(self, client_cert_path, subcaKey_path):
        with open(client_cert_path, 'rb') as cert_file:
            cert_data = cert_file.read()
            if pem.detect(cert_data):
                _, _, der_data = pem.unarmor(cert_data)
                cert = x509.Certificate.load(der_data)
                tbs_certificate_bytes = cert['tbs_certificate'].dump()
                signature = cert['signature_value'].native
                serial_number = cert.serial_number

        with open(subcaKey_path, "rb") as public_key_file:
            public_key_data = public_key_file.read()
            public_key = RSA.import_key(public_key_data)

        h = SHA256.new(tbs_certificate_bytes)
        try:
            pkcs1_15.new(public_key).verify(h, signature)
            # print("Signature verified successfully. The signature is valid.")
            return True, serial_number
        except(ValueError, TypeError):
            # print("Signature verification failed. The signature may be invalid or the certificate may be tampered.")
            return False, serial_number

    def cert_revocation(self,revoked_cert_file,client_cert_path, subcaKey_path):
        time_valid = ClientRegistration.verify_date(self, client_cert_path)
        signature_valid, serial_number = ClientRegistration.verify_signature(self, client_cert_path, subcaKey_path)
        current_date = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
        if not os.path.exists(revoked_cert_file):
            data = {"revokedCertificates": []}
        else:
            with open(revoked_cert_file, "r") as file:
                data = json.load(file)
        already_revoked = None
        for item in data["revokedCertificates"]:
            if item["SerialNumber"] == str(serial_number):
                already_revoked = item
                break
        if already_revoked:
            print(f"This certificate either has be compromised or not vaild since {already_revoked['revocationDate']}")
        elif not time_valid or not signature_valid:
            data["revokedCertificates"].append({
                "SerialNumber": str(serial_number),
                "revocationDate": current_date
            })
            with open(revoked_cert_file, "w") as file:
                json.dump(data, file, indent=4)
            #print("The certificate has been revoked or is invalid.")
        else:
            print("The certificate is valid.")
        
    def challenge_csr(self):
        # Challenge the client's CSR by signing a message
        # Load client certificate and private key, sign a message
        
        try:
            clientEmail = input("Enter your email: ")
            # Load certificate
            with open(client_cert_path, "rb") as cert_file:
                client_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_file.read())
            #Generating random message
            words = string.ascii_letters + string.digits
            message = ''.join(secrets.choice(words) for i in range(20))
            # Hash the message using SHA-256
            message_hash = SHA256.new(message.encode())
            # Sign the hashed message
            with open(client_private_key_path, 'rb') as key_file:
                private_key = RSA.import_key(key_file.read())
            signature = pkcs1_15.new(private_key).sign(message_hash)
            return signature, clientEmail, message, client_cert
        except Exception as e:
            print("Error in challenge_csr:", e)
            # Return None for all variables if an error occurs
            return None, None, None, None  
def main():
    options = ("""
                Choose an Option:                  

[1] - Client Registration & Certificate Generation 
[2] - Certificate Verification                     
[3] - Certificate Revocation                       
[4] - Exit                                           

""")

    client = ClientRegistration()
    subCA = SubCa()
    rootCA = RootCA()
    while True:
        try:
            print(options)
            user_input = input("Choose an option: ")
            if user_input == "1":
                check = client.client_register()
                if check == False:
                    print("Already Registered")
                else:
                    key, data, id = client.create_csr_for_client()
                    result = subCA.sign_client_csr(key, data, id)
                    print("Successfully generated a certificate.")
                    with open(client_cert_path, "wb") as cert_file:
                        cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, result))
            elif user_input == "2":
                chosen_subca = input("Enter the subCA: ")
                subcaKey_path = os.path.join(os.path.dirname(current_dir), f"../keys/subCA_keys/subca{chosen_subca}/subca{chosen_subca}_public_key.pem")
                client.cert_revocation(revoked_cert_file,client_cert_path,subcaKey_path)
            elif user_input == "3":
                # Call challenge_csr to obtain client certificate
                signature, clientEmail, message, client_cert = client.challenge_csr()
                validate = rootCA.validate_client(signature, clientEmail, message)
                if validate:
                    rootCA.revoke_list(client_cert)
            else:
                exit()
        except Exception as e:
            print("Error:", e)

if __name__ == "__main__":
    main()