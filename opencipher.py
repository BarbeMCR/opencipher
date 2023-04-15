#!/usr/bin/env python3

# BarbeMCR's OpenCipher
# An encryption/decryption application designed to obfuscate files and text
# A Python API is provided to use in any of your Python applications

# DISCLAIMER: BarbeMCR's OpenCipher is not meant for actual cryptographic purposes!
# It is not built to protect sensitive information. Use it only for futile work.
# While this application and its underlying API employ some security practices, you shouldn't trust either for securely encrypting things.

# Copyright (c) 2023  BarbeMCR
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""BarbeMCR's OpenCipher is an encryption library usable for obfuscating files and text.

Here is a list of documented functions in opencipher:
opencipher.encrypt
opencipher.encrypt_string
opencipher.encrypt_key
opencipher.authenticate
opencipher.hash
opencipher.decrypt
opencipher.decrypt_string
opencipher.decrypt_key
opencipher.check_tampering
opencipher.check_hash

When using any opencipher.* function, you should wrap it in a try-except that catches Exception exceptions.
This is because functions could raise many different kinds of exceptions, depending on the parameters given.
For example, if a wrong key is used to decrypt a file, depending on the wrong key contents, different exceptions could be raised.
In conclusion, wrap code like this:
try:
    opencipher.<function>(...)
    ...
except Exception:
    ...
"""

import random
import pickle
import hmac
import hashlib
import secrets
import sys
import io

def _print_main_menu():
    print("Welcome to BarbeMCR's OpenCipher!")
    print("This is the actual application interface.")
    print("For the API, write 'import opencipher' in a Python interpreter or script.")
    print("DISCLAIMER: do NOT use BarbeMCR's OpenCipher for actual cryptographic purposes!")
    print()
    print("Select an action from the list below:")
    print("1. Encrypt file")
    print("2. Decrypt file")
    print("3. Encrypt user input")
    print("4. Decrypt user input")
    print("5. Authenticate and hash encrypted products")
    print("6. Generate hash from products")
    print("7. Check tampering (digest validity)")
    print("8. Check corruption (hash validity)")
    print("0. Exit")
    choice = input("  ? ")
    return choice

def _encrypt_ui():
    print()
    print("Select a mode from the list below:")
    print("1. Use single table")
    print("2. Use multiple tables at single interval")
    print("3. Use multiple tables at multiple intervals")
    choice = input("  ? ")
    print()
    file = input("Insert the path to the file to encrypt: ")
    secret = input("Insert a secret key to use for authentication: ")
    match choice:
        case '1':
            encrypt(file, secret, multiple=False)
        case '2':
            encrypt(file, secret, multiple=True, intervals=False)
        case '3':
            encrypt(file, secret, multiple=True, intervals=True)
        case _:
            print("Invalid choice. Using single table...")
            encrypt(file, secret)
    print("Finished!")

def _decrypt_ui():
    print()
    print("Select the correct mode for your file from the list below:")
    print("1. Use single table")
    print("2. Use multiple tables at single interval")
    print("3. Use multiple tables at multiple intervals")
    choice = input("  ? ")
    print()
    file = input("Insert the path to the file to decrypt: ")
    key = input("Insert the path to the file's key: ")
    auth = input("Insert the path to the authentication file: ")
    secret = input("Insert the secret key used for authentication: ")
    match choice:
        case '1':
            decrypt(file, key, auth, secret, multiple=False)
        case '2':
            decrypt(file, key, auth, secret, multiple=True, intervals=False)
        case '3':
            decrypt(file, key, auth, secret, multiple=True, intervals=True)
        case _:
            print("Invalid choice. Using single table...")
            decrypt(file, key, auth, secret)
    print("Finished!")

def _encrypt_input_ui():
    print()
    print("Select a mode from the list below:")
    print("1. Use single table")
    print("2. Use multiple tables at single interval")
    print("3. Use multiple tables at multiple intervals")
    choice = input("  ? ")
    print()
    key = input("Insert a secret key: ")
    print()
    print("Now you can type the text (without international characters) you want to encrypt (hit 'return' to end input).")
    text = input()
    print()
    match choice:
        case '1':
            e = encrypt_string(text, key, multiple=False)
        case '2':
            e = encrypt_string(text, key, multiple=True, intervals=False)
        case '3':
            e = encrypt_string(text, key, multiple=True, intervals=True)
        case _:
            print("Invalid choice. Using single table...")
            e = encrypt_string(text, key)
    print("The encrypted text is:")
    print(e)

def _decrypt_input_ui():
    print()
    print("Select the correct mode for your text from the list below:")
    print("1. Use single table")
    print("2. Use multiple tables at single interval")
    print("3. Use multiple tables at multiple intervals")
    choice = input("  ? ")
    print()
    key = input("Insert the secret key: ")
    print()
    print("Now you can type the text you want to decrypt (hit 'return' to end input).")
    text = input()
    print()
    match choice:
        case '1':
            d = decrypt_string(text, key, multiple=False)
        case '2':
            d = decrypt_string(text, key, multiple=True, intervals=False)
        case '3':
            d = decrypt_string(text, key, multiple=True, intervals=True)
        case _:
            print("Invalid choice. Using single table...")
            d = decrypt_string(text, key)
    print("The decrypted text is:")
    print(d)

def _authenticate_ui():
    print()
    file = input("Insert the path to the .lock file: ")
    key = input("Insert the path to the .key file: ")
    secret = input("Insert the secret key to use: ")
    auth = input("Insert the output path (should end with .auth): ")
    authenticate(file, key, auth, secret)
    h = hash(file, key, auth)
    with open(auth, 'a') as a:
        a.write(h)
    print("Finished!")

def _hash_ui():
    print()
    file = input("Insert the path to the .lock file: ")
    key = input("Insert the path to the .key file: ")
    auth = input("Insert the path to the .auth file: ")
    h = hash(file, key, auth)
    print()
    print("The main hash is:")
    print(h)

def _check_tampering_ui():
    print()
    file = input("Insert the path to the .lock file: ")
    key = input("Insert the path to the .key file: ")
    auth = input("Insert the path to the .auth file: ")
    secret = input("Insert the secret key to use: ")
    t = check_tampering(file, key, auth, secret)
    if t:
        print()
        print("The files haven't been tampered with.")
    else:
        print()
        print("The files HAVE been tampered with.")

def _check_corruption_ui():
    print()
    file = input("Insert the path to the .lock file: ")
    key = input("Insert the path to the .key file: ")
    auth = input("Insert the path to the .auth file: ")
    c = check_hash(file, key, auth)
    if c:
        print()
        print("The files aren't corrupted.")
    else:
        print()
        print("The files ARE corrupted.")

def encrypt(file, secret, multiple=False, intervals=False):
    """Encrypt a file.

    Gets called like this:
    opencipher.encrypt(file, secret, [multiple], [intervals])

    file: the path to the file to encrypt
    secret: the secret key used for authentication
    multiple: whether to use multiple tables (False by default)
    intervals: whether to use multiple intervals in multiple tables mode (False by default)

    Writes <path>.(lock, key, auth):
    <path>.lock: the encrypted file
    <path>.key: the encrypted key to decrypt the file
    <path>.auth: the digests of the lock and the key and the hash of everything (including the digests)
    """
    random.seed(secrets.token_bytes(secrets.randbelow(512)+1))
    raw_key = random.getstate()
    table = {}
    for i in range(256):
        while True:
            #table[f"{i:#0{4}x}"] = f"{random.choice(range(255)):#0{4}x}"  # Applies padding such as 0xa -> 0x0a
            #if table[f"{i:#0{4}x}"] not in tuple(table.values())[:-1]:
                #break
            table[i] = random.choice(range(256))
            if table[i] not in tuple(table.values())[:-1]:
                break
    if not multiple:
        with open(file, 'rb') as f, open(f'{file}.lock', 'wb') as o:
            for b in f.read():
                o.write(table[b].to_bytes())
    else:
        interval = random.randint(1, 16)
        with open(file, 'rb') as f, open(f'{file}.lock', 'wb') as o:
            i = len(f.read())
            f.seek(0)
            while i > 0:
                for b in f.read(interval):
                    o.write(table[b].to_bytes())
                table = {}
                for n in range(256):
                    while True:
                        table[n] = random.choice(range(256))
                        if table[n] not in tuple(table.values())[:-1]:
                            break
                i -= interval
                if intervals:
                    interval = random.randint(1, 16)
    encrypt_key(raw_key, f'{file}.key', secret)
    authenticate(f'{file}.lock', f'{file}.key', f'{file}.auth', secret)
    h = hash(f'{file}.lock', f'{file}.key', f'{file}.auth')
    with open(f'{file}.auth', 'a') as a:
        a.write(h)

def encrypt_string(string, secret, multiple=False, intervals=False):
    """Encrypt a string.

    Gets called like this:
    opencipher.encrypt_string(string, secret, [multiple], [intervals])

    string: the string to encrypt
    secret: the secret key used for authentication
    multiple: whether to use multiple tables (False by default)
    intervals: whether to use multiple intervals in multiple tables mode (False by default)

    Return the encrypted string.
    """
    random.seed(secret)
    table = {}
    for i in range(256):
        while True:
            table[i] = random.choice(range(256))
            if table[i] not in tuple(table.values())[:-1]:
                break
    list_enc_string = []
    bstring = string.encode()
    if not multiple:
        for b in bstring:
            list_enc_string.append(hex(table[b]))
    else:
        interval = random.randint(1, 16)
        i = len(string)
        p = 0
        while i > 0:
            for b in bstring[p:p+interval]:
                list_enc_string.append(hex(table[b]))
            table = {}
            for n in range(256):
                while True:
                    table[n] = random.choice(range(256))
                    if table[n] not in tuple(table.values())[:-1]:
                        break
            i -= interval
            p += interval
            if intervals:
                interval = random.randint(1, 16)
    enc_string = ':'.join(list_enc_string)
    return enc_string

def encrypt_key(raw_key, key, secret):
    """Encrypt an OpenCipher key.

    Gets called like this:
    opencipher.encrypt_key(raw_key, key, secret)

    raw_key: the unencrypted key object (a random.getstate() return value or compatible)
    key: the path to write the encrypted key to
    secret: the secret key used for authentication

    Writes <path>.key: the encrypted key
    """
    random.seed(secret)
    table = {}
    for i in range(256):
        while True:
            table[i] = random.choice(range(256))
            if table[i] not in tuple(table.values())[:-1]:
                break
    with open(key, 'wb') as k:
        for b in pickle.dumps(raw_key):
            k.write(table[b].to_bytes())

def decrypt(file, key, auth, secret, multiple=False, intervals=False):
    """Decrypt a file.

    Gets called like this:
    opencipher.decrypt(file, key, auth, secret, [multiple], [intervals])

    file: the path to the file to decrypt
    key: the path to key used to decrypt the file
    auth: the path to the authentication file
    secret: the secret key used for authentication
    multiple: whether to use multiple tables (False by default)
    intervals: whether to use multiple intervals in multiple tables mode (False by default)

    Writes <path> from <path>.lock
    """
    if check_hash(file, key, auth) and check_tampering(file, key, auth, secret):
        raw_key = decrypt_key(key, secret)
        random.setstate(raw_key)
        table = {}
        for i in range(256):
            while True:
                table[i] = random.choice(range(256))
                if table[i] not in tuple(table.values())[:-1]:
                    break
        if not multiple:
            with open(file, 'rb') as o, open(file.removesuffix('.lock'), 'wb') as f:
                for b in o.read():
                    for k, v in table.items():
                        if b == v:
                            f.write(k.to_bytes())
        else:
            interval = random.randint(1, 16)
            with open(file, 'rb') as o, open(file.removesuffix('.lock'), 'wb') as f:
                i = len(o.read())
                o.seek(0)
                while i > 0:
                    for b in o.read(interval):
                        for k, v in table.items():
                            if b == v:
                                f.write(k.to_bytes())
                    table = {}
                    for n in range(256):
                        while True:
                            table[n] = random.choice(range(256))
                            if table[n] not in tuple(table.values())[:-1]:
                                break
                    i -= interval
                    if intervals:
                        interval = random.randint(1, 16)

def decrypt_string(enc_string, secret, multiple=False, intervals=False):
    """Decrypt a string.

    Gets called like this:
    opencipher.decrypt_string(enc_string, secret, [multiple], [intervals])

    enc_string: the string to decrypt
    secret: the secret key used for authentication
    multiple: whether to use multiple tables (False by default)
    intervals: whether to use multiple intervals in multiple tables mode (False by default)

    Return the decrypted string.
    """
    random.seed(secret)
    table = {}
    for i in range(256):
        while True:
            table[i] = random.choice(range(256))
            if table[i] not in tuple(table.values())[:-1]:
                break
    bstring = enc_string.split(':')
    list_string = []
    if not multiple:
        for b in bstring:
            for k, v in table.items():
                if int(b, 16) == v:
                    list_string.append(k.to_bytes().decode())
    else:
        interval = random.randint(1, 16)
        i = len(enc_string)
        p = 0
        while i > 0:
            for b in bstring[p:p+interval]:
                for k, v in table.items():
                    if int(b, 16) == v:
                        list_string.append(k.to_bytes().decode())
            table = {}
            for n in range(256):
                while True:
                    table[n] = random.choice(range(256))
                    if table[n] not in tuple(table.values())[:-1]:
                        break
            i -= interval
            p += interval
            if intervals:
                interval = random.randint(1, 16)
    string = ''.join(list_string)
    return string

def decrypt_key(key, secret):
    """Decrypt an OpenCipher key.

    Gets called like this:
    opencipher.decrypt_key(key, secret)

    key: the path to read the encrypted key from
    secret: the secret key used for authentication

    Return raw_key (a random.getstate() return value or compatible unencrypted key object).
    """
    random.seed(secret)
    table = {}
    r = io.BytesIO()
    for i in range(256):
        while True:
            table[i] = random.choice(range(256))
            if table[i] not in tuple(table.values())[:-1]:
                break
    with open(key, 'rb') as e:
        for b in e.read():
            for k, v in table.items():
                if b == v:
                    r.write(k.to_bytes())
    r.seek(0)
    raw_key = pickle.loads(r.read())
    return raw_key

def authenticate(lock, key, auth, secret):
    """Generate digests for lock and key with secret.

    Gets called like this:
    opencipher.authenticate(lock, key, auth, secret)

    lock: the path to the encrypted file
    key: the path to the encrypted key to the encrypted file
    auth: the path to write the digests to
    secret: the secret key to use

    Writes <path>.auth: the digests storage
    """
    with open(lock, 'rb') as l, open(key, 'rb') as k:
        lock_digest = hmac.new(secret.encode(), l.read(), 'sha512').hexdigest()
        key_digest = hmac.new(secret.encode(), k.read(), 'sha512').hexdigest()
    with open(auth, 'w') as a:
        a.write(lock_digest)
        a.write(key_digest)

def hash(lock, key, auth):
    """Generate a single hash for lock, key and auth.

    Gets called like this:
    opencipher.hash(lock, key, auth)

    lock: the path to the encrypted file
    key: the path to the encrypted key to the encrypted file
    auth: the path to the digests

    Return h: the computed SHA-512 hash
    """
    with open(lock, 'rb') as l, open(key, 'rb') as k, open(auth, 'rb') as a:
        all_bytes = l.read() + k.read() + a.read(256)
    h = hashlib.sha512(all_bytes).hexdigest()
    return h

def check_tampering(lock, key, auth, secret):
    """Compare actual digests with stored digests for lock and key.

    Gets called like this:
    opencipher.check_tampering(lock, key, auth, secret)

    lock: the path to the encrypted file
    key: the path to the encrypted key to the encrypted file
    auth: the path to read the digests from
    secret: the secret key to use

    Return True if the digests are the same or False if they aren't.
    """
    with open(auth, 'r') as a:
        a.seek(0)
        stored_lock_digest = a.read(128)
        a.seek(128)
        stored_key_digest = a.read(128)
    with open(lock, 'rb') as l, open(key, 'rb') as k:
        lock_digest = hmac.new(secret.encode(), l.read(), 'sha512').hexdigest()
        key_digest = hmac.new(secret.encode(), k.read(), 'sha512').hexdigest()
    return hmac.compare_digest(stored_lock_digest, lock_digest) and hmac.compare_digest(stored_key_digest, key_digest)

def check_hash(lock, key, auth):
    """Compare actual hash with stored hash for lock, key and auth.

    Gets called like this:
    opencipher.check_hash(lock, key, auth)

    lock: the path to the encrypted file
    key: the path to the encrypted key to the encrypted file
    auth: the path to the digests

    Return True if the hashes are the same or False if they aren't.
    """
    with open(auth, 'r') as a:
        a.seek(256)
        stored_h = a.read(128)
    with open(lock, 'rb') as l, open(key, 'rb') as k, open(auth, 'rb') as a:
        a.seek(0)
        all_bytes = l.read() + k.read() + a.read(256)
    h = hashlib.sha512(all_bytes).hexdigest()
    return stored_h == h

if __name__ == '__main__':
    choice = _print_main_menu()
    match choice:
        case '1':
            _encrypt_ui()
        case '2':
            _decrypt_ui()
        case '3':
            _encrypt_input_ui()
        case '4':
            _decrypt_input_ui()
        case '5':
            _authenticate_ui()
        case '6':
            _hash_ui()
        case '7':
            _check_tampering_ui()
        case '8':
            _check_corruption_ui()
        case _:
            sys.exit()
