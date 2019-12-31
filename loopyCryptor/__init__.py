try:
    from Crypto.Cipher import AES, PKCS1_v1_5
    from Crypto import Random
    from Crypto.PublicKey import RSA
except:
    raise ImportError(
        "LoopyCryptor depends on Crypto, "
        "which was not found, please `pip install pycryptodome`.\n"
        "If there's still an error, please go to "
        "https://pycryptodome.readthedocs.io/en/latest/src/installation.html"
        "to make sure you have successfully install Crypto"
    )

from .Cryptor import Cryptor

set_AES_key = lambda AES_key: Cryptor.set_AES_key(AES_key)
set_RSA_key = lambda pri_key, pub_key: Cryptor.set_RSA_key(pri_key, pub_key)

generate_RSA_key = lambda: Cryptor.generate_RSA_key()
generate_AES_key = lambda: Cryptor.generate_AES_key()

AES_encrypt = lambda text, key: Cryptor.AES_encrypt(text, key)
AES_decrypt = lambda byte, key: Cryptor.AES_decrypt(byte, key)
RSA_encrypt = lambda byte, public_key: Cryptor.RSA_encrypt(byte, public_key)
RSA_decrypt = lambda byte, private_key: Cryptor.RSA_decrypt(byte, private_key)
