# BarbeMCR's Opencipher
An encryption/decryption application and API designed to obfuscate files and text

**_DISCLAIMER: BarbeMCR's OpenCipher is not meant for actual cryptographic purposes!_**

It is *not* built to protect sensitive information. Use it *only* for futile work.

While this application and its underlying API employ some security practices, you *shouldn't* trust either for securely encrypting things.

## BarbeMCR's OpenCipher API

To import the BarbeMCR's OpenCipher module, just put `import opencipher` in your script.

Here is a list of all "public" functions of the `opencipher` namespace:

- `opencipher.encrypt(file:str, secret:str, multiple:bool=False, intervals:bool=False) -> None`
- `opencipher.encrypy_string(string:str, secret:str, multiple:bool=False, intervals:bool=False) -> str`
- `opencipher.encrypt_key(raw_key:tuple, key:str, secret:str) -> None`
- `opencipher.authenticate(lock:str, key:str, auth:str, secret:str) -> None`
- `opencipher.hash(lock:str, key:str, auth:str) -> str`
- `opencipher.decrypt(file:str, key:str, auth:str, secret:str, multiple:bool=False, intervals:bool=False) -> None`
- `opencipher.decrypt_string(enc_string:str, secret:str, multiple:bool=False, intervals:bool=False) -> str`
- `opencipher.decrypt_key(key:str, secret:str) -> tuple`
- `opencipher.check_tampering(lock:str, key:str, auth:str, secret:str) -> bool`
- `opencipher.check_hash(lock:str, key:str, auth:str) -> bool`

While there are several other `opencipher._*_ui` functions, those are only used for the application interface. You can ignore those when using the API.

You **should** always wrap `opencipher.*` functions in a try-except as follows:

```python
try:
    opencipher.<function>(*<arguments>)
    ...
except Exception:
    ...
```
