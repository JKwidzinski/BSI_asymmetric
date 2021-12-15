"""
Authors: Jakub Kwidziński, Jeremi Rycharski
"""
from Crypto import Random
from Crypto.Cipher import AES, Blowfish, DES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from struct import pack
from tinyec import registry
import hashlib, secrets, base64

DES_BLOCK_SIZE = 32
curve = registry.get_curve('brainpoolP256r1')

def aes_encrypt(key, msg):
    """This function encrypts given message using AES with given key.

    Args:
        key (bytes): aes key
        msg (string): message to encrypt

    Returns:
        nonce (bytes): A value that must never be reused for any other encryption done with this key 
        encrypted_msg (bytes): encrypted message
        tag : encryption tag
    """
    aes = AES.new(key, AES.MODE_EAX)
    nonce = aes.nonce
    encrypted_msg, tag = aes.encrypt_and_digest(msg.encode('ascii'))
    return nonce, encrypted_msg, tag

def aes_decrypt(key, nonce, encrypted_msg, tag):
    """This function decrypts given message with AES using given key.

    Args:
        key (bytes): Encryption key
        nonce (bytes): A value that must never be reused for any other encryption done with this key 
        encrypted_msg (bytes): Encrypted message
        tag : Encryption tag

    Returns:
        decrypted_msg (string): Decrypted message
    """
    aes = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted_msg = aes.decrypt(encrypted_msg)
    try:
        aes.verify(tag)
        return decrypted_msg.decode('ascii')
    except:
        return False

def des_encrypt(key, msg):
    """This function encrypts given message using DES with given key.

    Args:
        key (bytes): Encryption key
        msg (string): Message to encrypt

    Returns:
        encrypted_msg (bytes): Encrypted message
    """
    des = DES.new(key, DES.MODE_ECB)
    encrypted_msg = des.encrypt(pad(msg.encode('utf-8'), DES_BLOCK_SIZE))
    return encrypted_msg

def des_decrypt(key, encrypted_msg):
    """This function decrypts given message with DES using given key.

    Args:
        key (bytes): Encryption key
        encrypted_msg (bytes): Encrypted message

    Returns:
        decrypted_msg (string): Decrypted message
    """
    des = DES.new(key, DES.MODE_ECB)
    decrypted_msg = unpad(des.decrypt(encrypted_msg), DES_BLOCK_SIZE).decode('utf-8')
    return decrypted_msg

def blowfish_encrypt(key, msg):
    """This function encrypts given message using Blowfish with given key.

    Args:
        key (bytes): Encryption key
        msg (string): Message to encrypt

    Returns:
        encrypted_msg (bytes): Encrypted message
    """
    bs = Blowfish.block_size
    iv = Random.new().read(bs)
    msg = msg.encode('ascii')
    blowfish = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    plen =  bs - len(msg) % bs
    padding = [plen]*plen
    padding = pack('b'*plen, *padding)
    encrypted_msg = blowfish.iv + blowfish.encrypt(msg + padding)
    return encrypted_msg

def blowfish_decrypt(key, encrypted_msg):
    """This function decrypts given message with Blowfish using given key.

    Args:
        key (bytes): Encryption key
        encrypted_msg (bytes): Encrypted message

    Returns:
        decrypted_msg (string): Decrypted message
    """
    bs = Blowfish.block_size
    iv = encrypted_msg[:bs]
    encrypted_msg = encrypted_msg[bs:]
    blowfish = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    decrypted_msg = blowfish.decrypt(encrypted_msg)
    return decrypted_msg.decode('ascii')

def rsa_generate_keys():
    """This function generates private and public RSA keys.

    Returns:
        privatekey : Generated private key
        publickey : Generated public key
    """
    modulus_length = 256*4
    privatekey = RSA.generate(modulus_length, Random.new().read)
    publickey = privatekey.publickey()
    return privatekey, publickey

def rsa_encrypt (publickey, message):
    """This function encrypts given message using generated key.

    Args:
        publickey : Public key used only to encrypt
        message (string): Message to encrypt

    Returns:
        encoded_encrypted_msg : Encrypted message
    """
    encryptor = PKCS1_OAEP.new(publickey)
    encrypted_msg = encryptor.encrypt(message)
    encoded_encrypted_msg = base64.b64encode(encrypted_msg)
    return encoded_encrypted_msg

def rsa_decrypt(privatekey, encoded_encrypted_msg):
    """This function decrypts message using private key.

    Args:
        privatekey : Private key used only to decrypt a message.
        encoded_encrypted_msg : Encrypted message

    Returns:
        decoded_decrypted_msg : Decrypted message
    """
    decoded_encrypted_msg = base64.b64decode(encoded_encrypted_msg)
    decryptor = PKCS1_OAEP.new(privatekey)
    decoded_decrypted_msg = decryptor.decrypt(decoded_encrypted_msg)
    return decoded_decrypted_msg

def ecc_generate_keys():
    """This function generates private and public keys.

    Returns:
        privatekey : Private key used only to decrypt
        publickey : Public key used only to encrypt
    """
    privatekey = secrets.randbelow(curve.field.n)
    publickey = privatekey * curve.g     
    return privatekey, publickey

def encrypt_AES_GCM(msg, secretKey):
    """AES encrypt using GCM mode.

    Args:
        msg (string): Message to encrypt
        secretKey (bytes) : Encryption key

    Returns:
        ciphertext (bytes): Encrypted message
        aesCipher.nonce (bytes): A value that must never be reused for any other encryption done with this key 
        authTag : Encryption tag
    """
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag)

def decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey):
    """AES decrypt using GCM mode

    Args:
        ciphertext (bytes): Encrypted message
        nonce ([type]): A value that must never be reused for any other encryption done with this key 
        authTag : Encryption tag
        secretKey (bytes): Encryption key

    Returns:
        plaintext (string): Decrypted message
    """
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext

def ecc_point_to_256_bit_key(point):
    """Don't really know what it does tbh.

    Args:
        point : Some sort of point

    Returns:
        sha : something digested :)       
    """
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()

def ecc_encrypt(msg, pubKey):
    """Encrypts message using ECC with generated key.

    Args:
        msg (string): Message to encrypt
        pubKey : Public key used only to encrypt

    Returns:
        ciphertext (bytes): Encrypted message
        nonce : A value that must never be reused for any other encryption done with this key
        authTag : Encryption tag
        ciphertextPubKey : Public key used only to encrypt
    """
    msg = msg.encode('ascii')
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    sharedECCKey = ciphertextPrivKey * pubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    ciphertext, nonce, authTag = encrypt_AES_GCM(msg, secretKey)
    ciphertextPubKey = ciphertextPrivKey * curve.g
    return (ciphertext, nonce, authTag, ciphertextPubKey)

def ecc_decrypt(encryptedMsg, privKey):
    """This function decrypts given message with generated private key.

    Args:
        encryptedMsg : Encrypted message with necessary data 
        privKey : Private key used only to decrypt message

    Returns:
        plaintext (string): decrypted message
    """
    (ciphertext, nonce, authTag, ciphertextPubKey) = encryptedMsg
    sharedECCKey = privKey * ciphertextPubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    plaintext = decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
    return plaintext.decode('ascii')

privKey = secrets.randbelow(curve.field.n)
pubKey = privKey * curve.g
encryptedMsg = ecc_encrypt('docendo discimus', pubKey)
decryptedMsg = ecc_decrypt(encryptedMsg, privKey)
print(encryptedMsg[0])
print(decryptedMsg)

#privatekey, publickey = rsa_generate_keys()
#encrypted_msg = rsa_encrypt(publickey, 'docendo discimus')
#print(rsa_decrypt(privatekey, encrypted_msg))

#encrypted_msg = des_encrypt(b'abcdabcd', 'docendo discimus')
#print(des_decrypt(b'abcdabcd', encrypted_msg))

#encrypted_msg = blowfish_encrypt(b'abcdabcdabcdabcd', 'docendo discimus')
#print(blowfish_decrypt(b'abcdabcdabcdabcd', encrypted_msg))

#nonce, encrypted_msg, tag = aes_encrypt(b'abcdabcdabcdabcdabcdabcdabcdabcd', 'docendo discimus')
#print(aes_decrypt(b'abcdabcdabcdabcdabcdabcdabcdabcd', nonce, encrypted_msg, tag))