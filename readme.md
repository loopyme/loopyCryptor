# loopyCrypto

Install it with `pip install loopyCrypto`

## Introduction

What I've done here is wrap part of `pycryptodome` and `pickle` functions up with a 'pythonic' interface, which is easy to use. What's more, it can encrypt **any kinds of python objects**, handle it properly and gives the output of the given type. 

In short, I am trying to make a Cryptor that can help me as much as possible not to think about `bytes`, `string`, `byte boundary` and so many problems when I am trying to build a encrypted chat room.

## Docs

It's [here](http://api.loopy.tech/loopyCrypto/)

## Examples

 - RSA
    ``` python
    import loopyCryptor

    # generate a pair of key
    public_key, private_key = loopyCryptor.generate_RSA_key()

    # encrypt
    obj = [123,"HELLO",None,{"How are you?":b"I am fine and you?"}]
    cipher_byte = loopyCryptor.RSA_encrypt(obj,public_key)

    # decrypt
    decrypt_obj = loopyCryptor.RSA_decrypt(cipher_byte,private_key)

    # result
    print(decrypt_obj)
    print(decrypt_obj==obj)
    print(list(map(type, decrypt_obj)))
    
    #  [123, 'HELLO', None, {'How are you?': b'I am fine and you?'}] 
    # True 
    # [<class 'int'>, <class 'str'>, <class 'NoneType'>, <class 'dict'>]
    ```
 - AES
    ``` python
    import loopyCryptor
    # generate a key
    AES_key = loopyCryptor.generate_AES_key()

    # encrypt
    obj = [123,"HELLO",None,{"How are you?":b"I am fine and you?"}]
    cipher_byte = loopyCryptor.AES_encrypt(obj,AES_key)

    # decrypt
    decrypt_obj = loopyCryptor.AES_decrypt(cipher_byte,AES_key)

    # result
    print(decrypt_obj)
    print(decrypt_obj==obj)
    print(list(map(type, decrypt_obj))) 

    # [123, 'HELLO', None, {'How are you?': b'I am fine and you?'}] 
    # True 
    # [<class 'int'>, <class 'str'>, <class 'NoneType'>, <class 'dict'>]
    ```
 - [Here](https://github.com/loopyme/chat_room/tree/loopyme) is an example of using `loopyCrypto` to build an Encrypted Chat Room.
- The following code is how do I use it:
   ```python
   from loopyCryptor import encrypt, decrypt, generate_AES_key

   my_obj = [1,2,3] # some object i want to save

   key_pair = generate_RSA_key(set_default=True)
   with open("./my_obj","wb") as f:
      f.write(encrypt(my_obj, method = "RSA"))

   # when I want to use it:
   with open("./my_obj","rb") as f:
      decrypt_obj = decrypt(f.read(), method = "RSA")
   ```