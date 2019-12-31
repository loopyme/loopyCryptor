# loopyCrypto

Install it with `pip install loopyCrypto`

## Docs

It's [here](http://api.loopy.tech/loopyCrypto/)

## Examples

 - RSA
    ``` python
    import loopyCryptor

    # generate a pair of key
    public_key, private_key = loopyCryptor.generate_RSA_key()

    # encrypt
    text = "I hate verilog."
    cipher_byte = loopyCryptor.RSA_encrypt(text,public_key)

    # decrypt
    decrypt_text = loopyCryptor.RSA_decrypt(cipher_byte,private_key)
    print(decrypt_text) # I hate verilog.
    ```
 - AES
    ``` python
    import loopyCryptor
    # generate a key
    AES_key = loopyCryptor.generate_AES_key()

    # encrypt
    text = "I hate verilog."
    cipher_byte = loopyCryptor.AES_encrypt(text,AES_key)

    # decrypt
    decrypt_text = loopyCryptor.AES_decrypt(cipher_byte,AES_key)
    print(decrypt_text) # I hate verilog.
    ```
 - [Here](https://github.com/loopyme/chat_room/tree/loopyme) is an example of using `loopyCrypto` to build an Encrypted Chat Room.