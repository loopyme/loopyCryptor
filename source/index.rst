

LoopyCryptor-0.1.0
==================

.. toctree::
   :maxdepth: 3
   :caption: Contents:

Introduction
============

What I've done here is wrap part of `pycryptodome` and `pickle` functions up with a 'pythonic' interface, which is easy to use. What's more, it can encrypt **any kinds of python objects**, handle it properly and gives the output of the given type. 

In short, I am trying to make a Cryptor that can help me as much as possible not to think about `bytes`, `string`, `byte boundary` and so many problems when I am trying to build a encrypted chat room.

Installation
============

`LoopyCryptor` has been released on pypi, so you can install it with `pip install loopyCryptor`

Examples
========
All functions are implemented in Class:Cryptor, but we use lambda functions to wrapped up the Cryptor functions. So you can use it easier. Like this:

.. code-block:: python

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
    
    # [123, 'HELLO', None, {'How are you?': b'I am fine and you?'}] 
    # True 
    # [<class 'int'>, <class 'str'>, <class 'NoneType'>, <class 'dict'>]

    ###############################################################################
    # AES
    
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

API
===
.. autoclass:: loopyCryptor.Cryptor.Cryptor
   :members:
   
Indices and tables
==================

* :`Code repository <https://github.com/loopyme/loopyCrypto>`_
* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
