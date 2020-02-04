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

set_AES_key = Cryptor.set_AES_key
set_RSA_key = Cryptor.set_RSA_key

generate_RSA_key = Cryptor.generate_RSA_key
generate_AES_key = Cryptor.generate_AES_key

AES_encrypt = Cryptor.AES_encrypt
AES_decrypt = Cryptor.AES_decrypt
RSA_encrypt = Cryptor.RSA_encrypt
RSA_decrypt = Cryptor.RSA_decrypt

md5 = Cryptor.md5