---
title: "cookieJar"
date: 2024-01-02T10:11:43-05:00
draft: false
---

a fun aspect of pentesting is finding interesting ways to get authenticated sessions running. usually, a session authentication relies on the user entering some kind of key (password) that corresponds to their user ID (username). however, in some cases an attacker can "revive" sessions using just the session cookies. 

i wrote `cookieJar` for exactly this purpose: extracting cookies from various browsers (and factor in the OS) and then use them to create authenticated sessions. the script handles different formats and encryption methods (see: `Cryptodome`) and can extract cookies related to all websites or a specific domain.

some limitiations of the script:
- if browsers update their cookie storage mechanisms (very likely), the script will stop working.
- accounts with 2FA will stop the script from working.
- sessions are managed server-side, so if specific parameters like user-agent, IP address, etc. don't line up, the script will stop working.
- consent + security risks...

`cookieJar` uses several libraries and modules to retrieve, decrypt, and manage browser cookies across multiple browsers and operating systems. arguably, the most important module i've used is `Cryptodome`, which is included in the [source repo](https://github.com/bilals12/cookieJar).

# Cryptodome

the `Cryptodome` module contains the `pycryptodome` library, which is used for secure hashing and encryption services. in the context of `cookieJar`, it's used for decrypting cookies. 

1. `AES.py`: used for decrypting cookies from browsers like chrome, opera, edge.

2. `KDF.py`: a key derivation function that's used to generate a cryptographic key from a password. used in the `PBKDF2` function in `cookieJar`.

3. `padding.py`: used in block cipher algorithms to ensure that the last block of data is the correct size. used in `unpad` to remove padding from the decrypted data.

4. `lz4.block`: part of the `lz4` library, which provides bindings for the LZ4 compression algorithm. used specifically for handling cookies from firefox, which uses the compression algorithm to store its cookies. 

# cookieJar

![flowchart](/download.png)

`cookieJar` is a comprehensive python script for security research and penetration testing, as it allows researchers to analyze the cookies stored by a browser, which can contain sensitive information such as session identifiers and login tokens. 

```http
<http.cookiejar.Cookie version=0 name='sessionid' value='1234567890abcdef' port=None port_specified=False domain='instagram.com' domain_specified=True domain_initial_dot=False path='/' path_specified=True secure=True expires=1672444800 discard=False comment=None comment_url=None rest={'HttpOnly': None}, rfc2109=False>
```

this cookie has the following properties:
- `name`: the name of the cookie (`sessionid`).
- `value`: the value of the cookie, usually a unique identifier that the server uses to recognize the client.
- `domain`: the domain that set the cookie (`instagram.com`).
- `path`: path on the domain where the cookie is valid. in this case, it's `/`, meaning the cookie is valid for the entire domain.
- `secure`: a boolean value indicating whether the cookie should only be sent over secure (`HTTPS`) connections.
- `expires`: expiration date of the cookie as a timestamp (`1672444800` corresponds to january 1st, 2024).
- `HttpOnly`: a flag indicating whether the cookie is inaccessible to javascript's `Document.cookie` API to mitigate XSS attacks.

the actual data stored in a cookie can vary greatly depending on the website and the purpose of the cookie. for example, a session cookie might contain a unique identifier that the server uses to keep track of your session, while a preference cookie might contain information about your preferred language or other settings.

when `cookieJar` collects cookies, it stores them in a `http.cookiejar.CookieJar` object. this object behaves like a list of `http.cookiejar.Cookie` objects, and you can iterate over it to access individual cookies.

```python
cookies = load()
for cookie in cookies:
  print(cookie)
```

this will print out all the cookies stored in the `CookieJar`, one per line.

## importing necessary libraries

the script first imports some standard and 3rd-party libraries. they provide the necessary functionalities for file handling, database operations, encryption and more.

```python
import base64
import configparser
import contextlib
import glob
import http.cookiejar
import json
import os
import struct
import subprocess
import sys
import tempfile
from io import BytesIO
from typing import Union
```

it also imports the `sqlite3` library, which is used to interact with SQLite databases that many browsers use to store cookies. if the `pysqlite2.dbapi2` module is available, it's used instead of the standard `sqlite3` module (improved performance + additional features).

```python
try:
    from pysqlite2 import dbapi2 as sqlite3
except ImportError:
    import sqlite3
```

for linux/BSD, the script imports either `dbus` or `jeepney`. these are used to interact with the d-bus message system, a mechanism that allows different parts of the system to communicate with each other. in this case, it's used to retrieve the encryption key for cookies from the system's keyring.

```python
if sys.platform.startswith('linux') or 'bsd' in sys.platform.lower():
    try:
        import dbus
        USE_DBUS_LINUX = True
    except ImportError:
        import jeepney
        from jeepney.io.blocking import open_dbus_connection
        USE_DBUS_LINUX = False
```

the `lz4.block` is imported for handling LZ4-compressed cookies from firefox. LZ4 is a fast, lossless compression algorithm that firefox uses to store its cookies.

```python
import lz4.block
```

finally, the script imports the aforementioned modules from the `Cryptodome` library.

```python
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Util.Padding import unpad
```

## defining constants + helper functions

the script defines a constant for the default chromium password, used as the key for encrypting cookies in chromium-based browsers. it also defines a custom exception class for browser cookie errors.

```python
class ChromiumBasedBrowser:
    ...
    def load(self):
        ...
        # decrypt the cookie value
        value = self._decrypt(value, enc_value)
        ...
    def _decrypt(self, value, encrypted_value):
        ...
        data = aes.decrypt_and_verify(encrypted_value[12:-16], tag)
        ...
        return data.decode()
```

the firefox class handles cookies from firefox, using the `lz4.block` module to decompress LZ4-compressed cookies.

```python
class Firefox:
    ...
    def __add_session_cookies_lz4(self, cj):
        ...
        json_data = json.loads(lz4.block.decompress(file_obj.read()))
        ...
```

## loading cookies from all browsers

the `load` function loads cookies from all supported browsers and returns them in a combined `http.cookiejar.CookieJar` object. this function iterates over a list of functions that load cookies from each supported browser, and adds all the cookies they return to a single `CookieJar`. 

```python
def load(domain_name=""):
    # function to load cookies from all supported browsers and return combined cookie jar
    cj = http.cookiejar.CookieJar()
    for cookie_fn in [chrome, chromium, opera, opera_gx, brave, edge, vivaldi, firefox, safari]:
        try:
            for cookie in cookie_fn(domain_name=domain_name):
                cj.set_cookie(cookie)
        except BrowserCookieError:
            pass
    return cj
```

the script includes a separate class for each browser, as each browser stores its cookies differently. these classes inherit from the `Browser` base class, which provides common functionality, and override the `load` method to implement specific cookie extraction and decryption.

for example, the `Chrome` class handles cookies from google chrome. 

```python
class Chrome(ChromiumBasedBrowser):
    def __init__(self, cookie_file=None, domain_name="", key_file=None):
        super().__init__(cookie_file, domain_name, key_file)
```

the firefox class handles cookies from firefox, but overrides the `load` method to handle firefox unique cookie storage format.

```python
class Firefox(Browser):
    def __init__(self, cookie_file=None, domain_name=""):
        super().__init__(cookie_file, domain_name)
    def load(self):
        ...
```

## decrypting cookies

the ability to decrypt encrypted cookies is the most important part of `cookieJar`. it's done using the `Cryptodome` library, which provides a variety of cryptographic recipes and primitives.

the decryption process varies depending on the browser and the OS. for example, chromium-based browsers on windows use the windows data protection API (DPAPI) to encrypt cookies, while on linux/macOS, they use AES encryption with a key derived from a predefined password.

the `_decrypt` method in the `ChromiumBasedBrowser` handles this decryption process. it first checks the OS, then uses the appropriate decryption method.

```python
def _decrypt(self, value, encrypted_value):
    # method to decrypt encoded cookies
    ...
    if sys.platform == 'win32':
        try:
            # try to decrypt using the Windows Chromium method
            decrypted_value = _crypt_unprotect_data(encrypted_value)
        except Exception:
            return value
    else:
        # for Linux & Mac, we have to remove the 'v10' or 'v11' prefix
        encrypted_value = encrypted_value[3:]
        nonce, tag = encrypted_value[:12], encrypted_value[-16:]
        cipher = AES.new(self.v10_key, AES.MODE_GCM, nonce=nonce)
        decrypted_value = cipher.decrypt_and_verify(encrypted_value[12:-16], tag)
    return decrypted_value.decode('utf-8')
```

in the case of windows, the `_crypt_unprotect_data` function is used to decrypt the cookie using the DPAPI. this function uses the `CryptUnprotectData` function from the `crypt32.dll` library, which is a part of the windows API.

```python
def _crypt_unprotect_data(
        cipher_text=b'', entropy=b'', reserved=None, prompt_struct=None, is_key=False
):
    ...
    if not ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(blob_in), ctypes.byref(desc), ctypes.byref(blob_entropy),
            reserved, prompt_struct, CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(blob_out)
    ):
        # if the function fails, raise a RuntimeError
        raise RuntimeError('Failed to decrypt the cipher text with DPAPI')  # raise an error
```

on linux/macOS, the script uses the AES algorithm from the `Cryptodome.Cipher` module to decrypt the cookies. the key for the AES encryption is derived from the predefined password using the PBKDF2 algorithm from the `Cryptodome.Protocol.KDF` module.

```python
aes = AES.new(self.v10_key, AES.MODE_GCM, nonce=nonce)
data = aes.decrypt_and_verify(encrypted_value[12:-16], tag)
```

## error handling

issues can arise when dealing with cookies. for example, if a browser's cookies are stored in a SQLite database, and that database is locked because the browser is currently using it, the script creates a temporary copy of the database to avoid a locking error.

```python
def _create_local_copy(cookie_file):
    ...
    with contextlib.closing(sqlite3.connect('file:{}?mode=ro'.format(pathname2url(cookie_file)), uri=True)) as conn:
        with tempfile.TemporaryFile() as tmp_file:
            for line in conn.iterdump():
                tmp_file.write('{}\n'.format(line).encode('utf-8'))
            tmp_file.seek(0)
            conn_temp = sqlite3.connect('file:{}?mode=rw'.format(pathname2url(tmp_file.name)), uri=True)
            return conn_temp
```

the script also includes a custom exception class: `BrowserCookieError`. it's raised when there's an error retrieving or decrypting cookies, this allows the script to fail gracefully and provide usefull error messages.

```python
class BrowserCookieError(Exception): pass
```

# conclusion

i wrote this for the same reason i wrote everything else: education. `cookieJar` illustrates key security concepts, specifically those related to web security, encryption, and data storage. 
