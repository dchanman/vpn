#!/usr/bin/env python
###############################################################################
# Cryptography.py
#
# This is the generic helper class containing APIs for all crypto related code
# 
# Note that I would have opted for a shorter name (eg. Crypto) except that would
# conflict with the PyCrypto package naming, resulting in a weird circular
# dependency collision nightmare.
###############################################################################

from Crypto.Hash import SHA256
from Crypto.Hash import HMAC
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto import Random

###############################################################################
# Constants
###############################################################################
SYMMETRIC_KEY_BLOCK_SIZE = AES.block_size
SYMMETRIC_KEY_IV_SIZE = 16
SYMMETRIC_KEY_KEY_SIZE = 32
HMAC_LENGTH = 64 # SHA256 is 64 charcaters long

###############################################################################
# Hashing with SHA256
###############################################################################
def hash(msg):
    """
    Returns a SHA256 hash of msg
    """
    sha256 = SHA256.new()
    sha256.update(msg)
    return sha256.hexdigest()

###############################################################################
# HMAC with SHA256
###############################################################################
def hmac(key, iv, msg, padding = " "):
    """
    Returns an HMAC for an IV and a message. Uses SHA256
    """
    while(len(msg) % 16 != 0):
        msg += padding
    
    hmac = HMAC.new(key, digestmod = SHA256.new())
    hmac.update(bytes(iv))
    hmac.update(bytes(msg))
    return hmac.hexdigest()

###############################################################################
# Symmetric Key Crypto with AES-256
###############################################################################
def symmetricKeyEncrypt(key, iv, plaintext, padding=" "):
    """
    Returns plaintext encrypted with AES in CBC mode with a given key and IV.
    Plaintext length needs to be a multiple of 16 in length.
    Default padding is a space character " "
    """
    while(len(plaintext) % 16 != 0):
        plaintext += padding    
    
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(plaintext)

def symmetricKeyDecrypt(key, iv, ciphertext):
    """
    Returns ciphertext decrypted with AES in CBC mode with a given key and IV
    """
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.decrypt(ciphertext)

def generateRandomIV():
    """
    Returns a random IV to be used with AES
    """
    return Random.new().read(SYMMETRIC_KEY_BLOCK_SIZE)

def generateSymmetricKey():
    """
    Returns a random 32-byte key (AES-256)
    """
    return Random.new().read(32)

###############################################################################
# Asymmetric Key Crypto with RSA
###############################################################################
def generateAsymmetricKey():
    """
    Returns two values: private key object and public key object
    """
    privateKey = RSA.generate(2048)
    return privateKey, privateKey.publickey()

def asymmetricKeyEncrypt(publicKey, plaintext):
    """
    Returns plaintext encrypted with RSA with a given public key
    """
    # 32 is a random parameter for compatibility only. The value will be ignored
    return publicKey.encrypt(plaintext, 32)

def asymmetricKeyDecrypt(privateKey, ciphertext):
    """
    Returns ciphertext decrypted with RSA with a given private key
    """
    return privateKey.decrypt(ciphertext)

def asymmetricKeySign(privateKey, msg):
    """
    Hashes and signs msg with a given private key
    """
    # 32 is a random parameter for compatibility only. The value will be ignored
    return privateKey.sign(hash(msg), 32)

def asymmetricKeyVerify(publicKey, msg, signature):
    """
    Verifies signature is correct for msg with a given public key
    """
    return publicKey.verify(hash(msg), signature)

###############################################################################
# Test code
###############################################################################
if __name__ == "__main__":
    import argparse
    import sys
    parser = argparse.ArgumentParser(description="Test executable for Crypto module")
    parser.add_argument(
        'message',
        type=str,
        nargs="?",
        help="Message to crypto")
    
    args = parser.parse_args()
    
    msg = args.message if args.message is not None else "hi i love ildar"
    print("Message: {}".format(msg))
    
    # Hashing
    hashResult = hash(msg)
    print("SHA256: {}".format(hashResult))
    
    # Symmetric Key Testing
    symKey = generateSymmetricKey()
    iv = generateRandomIV()
    print("Key: {}".format(symKey))
    print("IV: {}".format(iv))
    
    encrypted = symmetricKeyEncrypt(symKey, iv, msg)
    print("Encrytped: {}".format(encrypted))
    decrypted = symmetricKeyDecrypt(symKey, iv, encrypted)
    print("Decrypted: {}".format(decrypted))
    
    # HMAC
    hmacResult = hmac(symKey, iv, msg)
    print("HMAC: {}".format(hmacResult))
    
    # Asymmetric Key Testing
    privKey, pubKey = generateAsymmetricKey()
    print("Private key: {}".format(privKey))
    print("Public key: {}".format(pubKey))
    
    encrypted = asymmetricKeyEncrypt(pubKey, msg)
    print("Encrypted: {}".format(encrypted))
    decrypted = asymmetricKeyDecrypt(privKey, encrypted)
    print("Decrypted: {}".format(decrypted))
    
    signature = asymmetricKeySign(privKey, msg)
    print("Signature: {}".format(signature))
    verify = asymmetricKeyVerify(pubKey, msg, signature)
    print("Verify: {}".format(verify))
