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

set_AES_key = lambda *arg,**args: Cryptor.set_AES_key(*arg,**args)
set_RSA_key = lambda *arg,**args: Cryptor.set_RSA_key(*arg,**args)

generate_RSA_key = lambda: Cryptor.generate_RSA_key()
generate_AES_key = lambda: Cryptor.generate_AES_key()

AES_encrypt = lambda *arg,**args: Cryptor.AES_encrypt(*arg,**args)
AES_decrypt = lambda *arg,**args: Cryptor.AES_decrypt(*arg,**args)
RSA_encrypt = lambda *arg,**args: Cryptor.RSA_encrypt(*arg,**args)
RSA_decrypt = lambda *arg,**args: Cryptor.RSA_decrypt(*arg,**args)
