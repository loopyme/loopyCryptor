import string
import unittest
from random import choice, randint

from Crypto.Random import get_random_bytes


class foo:
    cls_value = 0

    def __init__(self, value1, value2, cls_value):
        self.value1 = value1
        self.value2 = value2
        self.cls_value = cls_value

    def __eq__(self, other):
        return self.value1 == other.value1 and self.value2 == other.value2 and self.cls_value == other.cls_value


def bar(n):
    return n * bar(n - 1) if n != 1 else 1


class MyTestCase(unittest.TestCase):

    @staticmethod
    def random_str():
        return ''.join(choice(string.ascii_letters + string.digits) for _ in range(randint(10, 1000)))

    @staticmethod
    def random_list():
        return list(MyTestCase.random_str()) + list(range(randint(4, 20))) + [None]

    @staticmethod
    def random_byte():
        return get_random_bytes(randint(10, 1000))

    @staticmethod
    def random_obj():
        return foo(randint(1, 100), MyTestCase.random_byte(), MyTestCase.random_str())

    @staticmethod
    def ret_cls():
        return foo

    @staticmethod
    def ret_func():
        return bar

    def test_AES(self):
        from loopyCryptor import AES_encrypt, AES_decrypt, set_default_AES_key, generate_AES_key

        for random_obj in [MyTestCase.random_byte, MyTestCase.random_obj, MyTestCase.random_str,
                           MyTestCase.random_list, MyTestCase.ret_cls, MyTestCase.ret_func]:
            key = generate_AES_key()
            text = random_obj()
            encrypt_text = AES_encrypt(text, key)
            self.assertEqual(text, AES_decrypt(encrypt_text, key))

            key = generate_AES_key()
            set_default_AES_key(key)
            text = random_obj()
            encrypt_text = AES_encrypt(text)
            self.assertEqual(text, AES_decrypt(encrypt_text))

    def test_RSA(self):
        from loopyCryptor import RSA_encrypt, RSA_decrypt, set_default_RSA_key, generate_RSA_key

        for random_obj in [MyTestCase.random_byte, MyTestCase.random_obj, MyTestCase.random_str,
                           MyTestCase.random_list, MyTestCase.ret_cls, MyTestCase.ret_func]:
            key = generate_RSA_key()
            text = random_obj()
            encrypt_text = RSA_encrypt(text, key[0])
            self.assertEqual(text, RSA_decrypt(encrypt_text, key[1]))

            key = generate_RSA_key()
            set_default_RSA_key(*key)
            text = random_obj()
            encrypt_text = RSA_encrypt(text)
            self.assertEqual(text, RSA_decrypt(encrypt_text))


if __name__ == '__main__':
    unittest.main()
