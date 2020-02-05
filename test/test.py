import random
import string
import unittest


class MyTestCase(unittest.TestCase):
    @staticmethod
    def random_text():
        return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(random.randint(10, 1000)))

    def test_AES(self):
        from loopyCryptor import AES_encrypt, AES_decrypt, set_AES_key, generate_AES_key

        for i in range(3):
            key = generate_AES_key()
            text = MyTestCase.random_text()
            encrypt_text = AES_encrypt(text, key)
            self.assertEqual(text, AES_decrypt(encrypt_text, key))

            key = generate_AES_key()
            set_AES_key(key)
            text = MyTestCase.random_text()
            encrypt_text = AES_encrypt(text)
            self.assertEqual(text, AES_decrypt(encrypt_text))

    def test_RSA(self):
        from loopyCryptor import RSA_encrypt, RSA_decrypt, set_RSA_key, generate_RSA_key
        for i in range(3):
            key = generate_RSA_key()
            text = MyTestCase.random_text()
            encrypt_text = RSA_encrypt(text, key[0])
            self.assertEqual(text, RSA_decrypt(encrypt_text, key[1]))

            key = generate_RSA_key()
            set_RSA_key(*key)
            text = MyTestCase.random_text()
            encrypt_text = RSA_encrypt(text)
            self.assertEqual(text, RSA_decrypt(encrypt_text))


if __name__ == '__main__':
    unittest.main()
