"""
Authors: Jakub Kwidziński, Jeremi Rycharski
"""
from Crypto import Random
from Crypto.Cipher import AES, Blowfish, DES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA, ECC
from struct import pack
from tinyec import registry
import hashlib, secrets, binascii, base64

DES_BLOCK_SIZE = 32
curve = registry.get_curve('brainpoolP256r1')

def aes_encrypt(key, msg):
    aes = AES.new(key, AES.MODE_EAX)
    nonce = aes.nonce
    encrypted_msg, tag = aes.encrypt_and_digest(msg.encode('ascii'))
    return nonce, encrypted_msg, tag

def aes_decrypt(key, nonce, encrypted_msg, tag):
    aes = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted_msg = aes.decrypt(encrypted_msg)
    try:
        aes.verify(tag)
        return decrypted_msg.decode('ascii')
    except:
        return False

def des_encrypt(key, msg):
    des = DES.new(key, DES.MODE_ECB)
    encrypted_msg = des.encrypt(pad(msg.encode('utf-8'), DES_BLOCK_SIZE))
    return encrypted_msg

def des_decrypt(key, encrypted_msg):
    des = DES.new(key, DES.MODE_ECB)
    decrypted_msg = unpad(des.decrypt(encrypted_msg), DES_BLOCK_SIZE).decode('utf-8')
    return decrypted_msg

def blowfish_encrypt(key, msg):
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
    bs = Blowfish.block_size
    iv = encrypted_msg[:bs]
    encrypted_msg = encrypted_msg[bs:]
    blowfish = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    decrypted_msg = blowfish.decrypt(encrypted_msg)
    return decrypted_msg.decode('ascii')

def rsa_generate_keys():
   modulus_length = 256*4
   privatekey = RSA.generate(modulus_length, Random.new().read)
   publickey = privatekey.publickey()
   return privatekey, publickey

def rsa_encrypt (publickey, message):
   encrypted_msg = publickey.encrypt(message, 32)[0]
   encoded_encrypted_msg = base64.b64encode(encrypted_msg)
   return encoded_encrypted_msg

def rsa_decrypt(privatekey, encoded_encrypted_msg):
   decoded_encrypted_msg = base64.b64decode(encoded_encrypted_msg)
   decoded_decrypted_msg = privatekey.decrypt(decoded_encrypted_msg)
   return decoded_decrypted_msg

def ecc_generate_keys():
    privatekey = ECC.generate(curve='P-256')
    publickey = privatekey.public_key()
    return privatekey, publickey

def encrypt_AES_GCM(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag)

def decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext

def ecc_point_to_256_bit_key(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()

def ecc_encrypt(msg, pubKey):
    msg = msg.encode('ascii')
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    sharedECCKey = ciphertextPrivKey * pubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    ciphertext, nonce, authTag = encrypt_AES_GCM(msg, secretKey)
    ciphertextPubKey = ciphertextPrivKey * curve.g
    return (ciphertext, nonce, authTag, ciphertextPubKey)

def ecc_decrypt(encryptedMsg, privKey):
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

#encrypted_msg = des_encrypt(b'abcdabcd', 'docendo discimus')
#print(des_decrypt(b'abcdabcd', encrypted_msg))

#encrypted_msg = blowfish_encrypt(b'abcdabcdabcdabcd', 'docendo discimus')
#print(blowfish_decrypt(b'abcdabcdabcdabcd', encrypted_msg))

#nonce, encrypted_msg, tag = aes_encrypt(b'abcdabcdabcdabcdabcdabcdabcdabcd', 'docendo discimus')
#print(aes_decrypt(b'abcdabcdabcdabcdabcdabcdabcdabcd', nonce, encrypted_msg, tag))