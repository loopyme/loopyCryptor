import hashlib
from base64 import b64encode, b64decode

from Crypto import Random
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA


class Cryptor:
    """Cryptor is based on AES-CBC-16 and RSA_PKCS"""

    __AES_key = None
    __RSA_key = (None, None)

    def __init__(self):
        """
        init func
        :raise AttributeError: should not be instance
        """
        raise AttributeError("Cryptor should not be instance")

    @staticmethod
    def _to_byte(text):
        """
        make sure `text` is bytes

        :raise AttributeError: Text is not processable
        """
        if isinstance(text, str):
            return text.encode()
        elif isinstance(text, bytes):
            return text
        else:
            raise AttributeError(
                "Unable to convert {} to bytes.Text should be string or bytes".format(
                    type(text)
                )
            )

    @staticmethod
    def _to_str(text, do_convert=True):
        """
        make sure `text` is string if `do_convert`

        :raise AttributeError: Text is not processable
        """
        if not do_convert:
            return text
        elif isinstance(text, str):
            return text
        elif isinstance(text, bytes):
            return text.decode()
        else:
            raise AttributeError(
                "Unable to convert {} to string.Text should be string or bytes".format(
                    type(text)
                )
            )

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
        return Cryptor._to_byte(key)

    @staticmethod
    def _cut_bytes(bytes):
        """
        Split the bytes by fixed length

        :param bytes: bytes to be cut
        """
        cut_length = 3
        byte_list = [bytes[cut_length * i:cut_length * i + cut_length] for i in range(len(bytes) // cut_length)]
        if len(bytes) % cut_length != 0:
            byte_list.append(bytes[-(len(bytes) % cut_length):])
        return byte_list

    @staticmethod
    def _concat_byte_list(byte_list):
        """
        concat a byte list
        """
        res = b''
        for b in byte_list:
            res += b
        return res

    @classmethod
    def set_AES_key(cls, AES_key):
        """
        set a default AES_key

        :param AES_key: bytes/string AES_key
        """
        cls.__AES_key = Cryptor._to_byte(AES_key)

    @classmethod
    def set_RSA_key(cls, pub_key, pri_key):
        """
        set a default RSA_key

        :param pri_key: bytes/string public_key
        :param pri_key: bytes/string private_key
        """
        cls.__RSA_key = (Cryptor._to_byte(pub_key), Cryptor._to_byte(pri_key))

    @classmethod
    def generate_RSA_key(cls, ret_str=True):
        """
        generate a RSA key pair

        :param ret_str: bool type of return value. If ret_str, it will return string, otherwise, it will return bytes.
        :return public_pem: string/byte If ret_str, it will return string.
        :return private_pem: string/byte If ret_str, it will return string.
        """
        rsa = RSA.generate(1024, Random.new().read)
        private_pem = rsa.exportKey()
        public_pem = rsa.publickey().exportKey()
        return Cryptor._to_str(public_pem, ret_str), Cryptor._to_str(private_pem, ret_str)

    @classmethod
    def generate_AES_key(cls):
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

        :param text: byte/string Bytes/string to be encrypted
        :param key: byte AES key
        :return: byte Encrypted byte stream
        """
        byte = Cryptor._to_byte(text)
        key = Cryptor._validate_key(cls.__AES_key if key is None else key)

        byte += b"\0" * (16 - (len(byte) % 16))
        return AES.new(key, AES.MODE_CBC, key).encrypt(byte)

    @classmethod
    def AES_decrypt(cls, byte, key=None, ret_str=True):
        """
        Decrypt: Obtained the symmetric encrypted key, decrypt the byte stream and removed '\0',finally decoded\
         it into a string

        :param byte: byte/string Bytes/string to be decrypted
        :param key: byte AES key
        :param ret_str: bool type of return value. If ret_str, it will return string, otherwise, it will return bytes.
        :return: str Decrypted string
        """
        byte = Cryptor._to_byte(byte)
        key = Cryptor._validate_key(cls.__AES_key if key is None else key)
        plain_byte = AES.new(key, AES.MODE_CBC, key).decrypt(byte)

        return Cryptor._to_str(plain_byte.rstrip(b"\0"), ret_str)

    @classmethod
    def RSA_encrypt(cls, text, public_key=None):
        """
        Encrypt: import a RSA public key and use it to encrypt text

        :param text: byte/string Bytes/string to be encrypted
        :param public_key: byte RSA public_key
        :return: byte Encrypted byte stream
        """
        bytes = Cryptor._to_byte(text)
        bytes_list = Cryptor._cut_bytes(bytes)

        public_key = Cryptor._validate_key(
            public_key if public_key is not None else cls.__RSA_key[0]
        )
        PKCS1 = PKCS1_v1_5.new(RSA.importKey(public_key))
        cipher_bytes_list = map(lambda x: b64encode(PKCS1.encrypt(x)), bytes_list)

        return Cryptor._concat_byte_list(cipher_bytes_list)

    @classmethod
    def RSA_decrypt(cls, text, private_key=None, ret_str=True):
        """
        Decrypt: import a RSA public key and use it to decrypt text

        :param text: byte/string Bytes/string to be decrypted
        :param ret_str: bool type of return value. If ret_str, it will return string, otherwise, it will return bytes.
        :param private_key: byte RSA private_key
        :return: str Decrypted string
        """
        byte_list = Cryptor._to_byte(text).split(b'=')[:-1]
        private_key = Cryptor._validate_key(
            private_key if private_key is not None else cls.__RSA_key[1]
        )
        PKCS1 = PKCS1_v1_5.new(RSA.importKey(private_key))

        bytes_list = map(lambda x: PKCS1.decrypt(b64decode(x + b'='), "ERROR"), byte_list)
        bytes = Cryptor._concat_byte_list(bytes_list)
        return Cryptor._to_str(bytes, ret_str)

    @staticmethod
    def md5(content):
        """
        Run md5: If content is a list, it will update multiple times in items. Or it will return md5(content).

        :param content: list/byte/str If it's a list, it will update multiple times in items.
        :return: str md5 result in hexdigest
        """
        md5 = hashlib.md5()
        if isinstance(content, list):
            for item in content:
                md5.update(Cryptor._to_byte(item))
        else:
            md5.update(Cryptor._to_byte(content))
        return md5.hexdigest()
