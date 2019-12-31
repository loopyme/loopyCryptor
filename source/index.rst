

LoopyCryptor
============

.. toctree::
   :maxdepth: 2
   :caption: Contents:



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

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
