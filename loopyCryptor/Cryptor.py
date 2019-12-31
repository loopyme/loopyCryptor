import base64
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto import Random
from Crypto.PublicKey import RSA


class Cryptor:
    """Cryptor is based on AES-CBC-16 and RSA_PKCS"""

    __AES_key = __RSA_key = None

    def __init__(self):
        """
        init func
        :raise AttributeError: should not be instance
        """
        raise AttributeError("Cryptor should not be instance")

    @staticmethod
    def _validate_key(key):
        """
        check if key is not None
        :param key:
        :return: key
        :raise AttributeError: No valid key was passed in
        """
        if key is None:
            raise AttributeError("No valid key was passed in")
        return key
    
    @staticmethod
    def _to_byte(text):
        if isinstance(text,str):
            return text.encode()
        elif isinstance(text,bytes):
            return text
        else:
            raise AttributeError("Text should be string or bytes")

    @classmethod
    def set_AES_key(cls, AES_key):
        cls.__AES_key = AES_key

    @classmethod
    def set_RSA_key(cls, pri_key, pub_key):
        cls.__RSA_key = (pri_key, pub_key)

    @staticmethod
    def generate_RSA_key():
        """
        generate a RSA key pair

        :return public_pem: byte
        :return private_pem: byte
        """
        rsa = RSA.generate(1024, Random.new().read)
        private_pem = rsa.exportKey()
        public_pem = rsa.publickey().exportKey()
        return public_pem, private_pem

    @staticmethod
    def generate_AES_key():
        """
        Generate a AES key

        :return key: byte
        """
        return Random.get_random_bytes(16)

    @classmethod
    def AES_encrypt(cls, text, key=None):
        """
        Encrypt: Encode the string into a byte-stream, then add it to a multiple of 16, then obtained a \
        symmetric encryption key that is updated daily and then encrypt the string with the key.It is worth noting \
        that '\0' is used in the completion.

        :param text: str String to be encrypted
        :param key: byte AES key
        :return: byte Encrypted byte stream
        """
        key = cls._validate_key(cls.__AES_key if key is None else key)
        text += "\0" * (16 - (len(text.encode()) % 16))
        return AES.new(key, AES.MODE_CBC, key).encrypt(text.encode())

    @classmethod
    def AES_decrypt(cls, byte, key=None):
        """
        Decrypt: Obtained the symmetric encrypted key, decrypt the byte stream and removed '\0',finally decoded\
         it into a string

        :param byte: byte/string Bytes/string to be decrypted
        :param key: byte AES key
        :return: str Decrypted string
        """
        byte = cls._to_byte(byte)
        key = cls._validate_key(cls.__AES_key if key is None else key)
        plain_text = AES.new(key, AES.MODE_CBC, key).decrypt(byte)
        return plain_text.decode().rstrip("\0")

    @classmethod
    def RSA_encrypt(cls, byte, public_key=None):
        """
        Encrypt: import a RSA public key and use it to encrypt a byte stream

        :param byte: byte/string Bytes/string to be encrypted
        :param public_key: byte RSA public_key
        :return: byte Encrypted byte stream
        """
        byte = cls._to_byte(byte)
        public_key = cls._validate_key(
            public_key if public_key is not None else cls.__RSA_key[1]
        )
        rsa_key = RSA.importKey(public_key)
        cipher = PKCS1_v1_5.new(rsa_key)
        cipher_byte = base64.b64encode(cipher.encrypt(byte))
        return cipher_byte

    @classmethod
    def RSA_decrypt(cls, byte, private_key=None):
        """
        Decrypt: import a RSA public key and use it to decrypt a byte stream

        :param byte: byte/string Bytes/string to be decrypted
        :param private_key: byte RSA private_key
        :return: byte Decrypted byte
        """
        byte = cls._to_byte(byte)
        private_key = cls._validate_key(
            private_key if private_key is not None else cls.__RSA_key[0]
        )
        rsa_key = RSA.importKey(private_key)
        cipher = PKCS1_v1_5.new(rsa_key)
        text = cipher.decrypt(base64.b64decode(byte), "ERROR")
        return text
