

LoopyCryptor
============

.. toctree::
   :maxdepth: 3
   :caption: Contents:

Introduction
============

What I've done here is wrap part of `pycryptodome` functions up with a 'pythonic' interface, which is easy to use. What's more, it can automatically determine the type of input(`bytes`or`str`), handle it properly and gives the output of the given type. 

In short, I am trying to make a Cryptor that can help me as much as possible not to think about `bytes`, `string`, `byte boundary` and so many problems when I am trying to build a encrypted chat room.

Installation
============

`LoopyCryptor` has been released on pypi, so you can install it with `pip install loopyCryptor`

Examples
========
All functions are implemented in Class:Cryptor, but we use lambda functions to wrapped up the Cryptor functions. So you can use it easier. Like this:

.. code-block:: python

    import loopyCryptor

    ###############################################################################
    # RSA
    
    # generate a pair of key
    public_key, private_key = loopyCryptor.generate_RSA_key()

    # encrypt
    text = "I hate verilog."
    cipher_byte = loopyCryptor.RSA_encrypt(text,public_key)

    # decrypt
    decrypt_text = loopyCryptor.RSA_decrypt(cipher_byte,private_key)
    print(decrypt_text) # I hate verilog.

    ###############################################################################
    # AES
    
    # generate a key
    AES_key = loopyCryptor.generate_AES_key()

    # encrypt
    text = "I hate verilog."
    cipher_byte = loopyCryptor.AES_encrypt(text,AES_key)

    # decrypt
    decrypt_text = loopyCryptor.AES_decrypt(cipher_byte,AES_key)
    print(decrypt_text) # I hate verilog.

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
