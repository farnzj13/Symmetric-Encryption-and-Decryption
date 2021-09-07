# Symmetric-Encryption-and-Decryption

A university lab exercise involves extending existing `FileEncryptor.java` file to allow users to use:
- Symmetric Encryption or decryption operations
- Secret key and initialisation vector (IV) in Base64 encoding (for decryption)
- Input and output file paths

`enc`- keyword used to indicate encryption operation
`dec`- keyword used to indicate decryption operation

 `plaintext.txt`- text file to be encrypted

A secret key is randomly generated and output using Base64 encoding (Base64 javadoc). The secret key can also be provided for decryption encoded using Base64.


# How to run

Run command below to execue encryption. This will encrypt the file `plaintext.txt` as `ciphertext.enc` and printout the randomly generated secret key encoded as a base64 string.

```
% java FileEncryptor enc plaintext.txt ciphertext.enc
```
Run command below to decrypt the file `ciphertext.enc as plaintext.txt.
```
% java FileEncryptor dec ((base 64 encoded key)) ((base 64 IV)) ciphertext.enc plaintext.txt
```

