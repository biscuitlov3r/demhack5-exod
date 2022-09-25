import gnupg
import traceback

gpg = gnupg.GPG()

def generate_keys(password, contact_id):
    input_data = gpg.gen_key_input(key_type="RSA", key_length=1024, passphrase=password, name_email=contact_id)
    key = gpg.gen_key(input_data)
    return key

def encrypt_string(string, recipient, password, key):
    encrypted_data = gpg.encrypt(string.encode('utf-8'), recipient, sign=key, passphrase=password)
    return {"status": encrypted_data.status, "string": str(encrypted_data)}

def decrypt_string(encrypted_string, password):
    encrypted_string = str(encrypted_string)
    status = gpg.decrypt(encrypted_string, passphrase=password)
    if status.trust_level is not None and status.trust_level >= status.TRUST_FULLY:
            return {"data": status.data.decode('utf-8'), "status": status.status, "trust_level": status.trust_text,
                "key": status.key_id, "user": status.username}
    else:
        raise ValueError("Signature could not be verified!")

def encrypt_file(filename, recipient, password, key):
    with open(filename, 'rb') as f:
        status = gpg.encrypt_file(f, recipients=[recipient], output=filename+".gpg", sign=key, passphrase=password)
        return {"status": status.status, "filename": filename+".gpg"}

def decrypt_file(filename, password):
    with open(filename, 'rb') as f:
        status = gpg.decrypt_file(f, passphrase=password, output=filename.removesuffix('.gpg'))
        print(status.trust_text)
        if status.trust_level is not None and status.trust_level >= status.TRUST_FULLY:
            return {"status": status.status, "trust_level": status.trust_text,
                "key": status.key_id, "user": status.username, "file": filename.removesuffix('.gpg')}
        else:
            raise ValueError("Signature could not be verified!")