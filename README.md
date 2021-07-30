# Py-Encryptor
## What's New
```
* Added New Encryption Class Bush_Encryption, RSA_Encryption (ASymmetric)
* Added Doc For Every Function
* Added File Encryption
* Many Bugs Fixed
* Upgraded To Version 2.3
* Many Exceptions Catched Under Try Except
```
## Installation
```commandline
pip install Py-Encryptor
```
## Using git
```commandline
git clone https://github.com/pmk456/Encryptor
cd Encryptor
python setup.py install
```
## Usage
### Generate Private And Public Keys For RSA_Encryption
```python
from Encryptor import RSA_Encryption
RSA_Encryption.generate_keys()
```
### Sign Data Using RSA
```python
# Supported Algorithms For Signing = ['SHA-1', 'SHA-224', 'SHA-256', 'SHA-384', 'SHA-512', "MD5"]
from Encryptor import RSA_Encryption
cipher = RSA_Encryption(public_file="public_key.pem")
cipher.sign(b"data", algo="SHA-1")
# Output
# Signature Of Data:
# b'm\xa6\xf1(\xaa13\x03F5\x10g\xb0)\xf2\xae/7\xb1G\xbf\x00\xe8I-\xc8T\r\xcc\t\x830\x11\x02\xa2\xff\x93\xf1\xf5\t\xfa\xb4\x97\x03\xd5b\xdf\xa1\xa8B\xbcv\x12\x04\x97\xc0\\\x1c\xd6\xb3\xdc\xb8c\xd5'
```
### Verify Signature of Data
```python
# Supported Algorithms For Signing = ['SHA-1', 'SHA-224', 'SHA-256', 'SHA-384', 'SHA-512', "MD5"]
from Encryptor import RSA_Encryption
cipher = RSA_Encryption(public_file="public_key.pem", private_file="private_key.pem")
data = b'm\xa6\xf1(\xaa13\x03F5\x10g\xb0)\xf2\xae/7\xb1G\xbf\x00\xe8I-\xc8T\r\xcc\t\x830\x11\x02\xa2\xff\x93\xf1\xf5\t\xfa\xb4\x97\x03\xd5b\xdf\xa1\xa8B\xbcv\x12\x04\x97\xc0\\\x1c\xd6\xb3\xdc\xb8c\xd5'
print(cipher.verify_signature(b"Data", data))
# Output
# (True, "SHA-1")
```
### Sign A File Using RSA
```python
# Supported Algorithms For Signing = ['SHA-1', 'SHA-224', 'SHA-256', 'SHA-384', 'SHA-512', "MD5"]
from Encryptor import RSA_Encryption
cipher = RSA_Encryption(public_file="public_key.pem", private_file="private_key.pem")
cipher.sign_file("path", algo="SHA-1")
# Output
# Signature Of File
```
### Verify Signature of A File
```python
# Supported Algorithms For Signing = ['SHA-1', 'SHA-224', 'SHA-256', 'SHA-384', 'SHA-512', "MD5"]
from Encryptor import RSA_Encryption
cipher = RSA_Encryption(public_file="public_key.pem", private_file="private_key.pem")
data = b'4\xf5\x0bu\x10\xab\x9cA}\xce\x96Z,[\xd7Cp\xe0\xcb\x97Xew\xf7\n\xd9\x95\x1dy\x87\x11\x1d\xf88\xba2\xddR\xec\x13\x175sv@\x9f\xd0\xfe\xa2\xd7\n\x1c\x18O\xc4\xe8U\x94bg%\xec\xbfz'
cipher.verify_file("path", data)
# Output
# (True, "SHA-1")
```
### Encrypt File Using Bush
```python
from Encryptor import Bush_Encryption
cipher = Bush_Encryption("KeyToUse")
cipher.file_encrypt('path')
# Output
# Same File With .enc Extension
```
### Encrypt File Using Fernet
```python
from Encryptor import Fernet_Encryption
cipher = Fernet_Encryption(key='keytouse')
cipher.file_encrypt('path')
# Output
"""
Encrypted File with Extension .enc will be In The Same Path
"""
```
### Encrypt File Using AES
```python
from Encryptor import AES_Encryption
cipher = AES_Encryption(key='keytouse', iv='this is iv 45611')
print(cipher.file_encrypt('path'))
# Output
"""
File Successfully Encrypted With Given Key
In Case Of any exception:
Something Went Wrong During Encryption Of The File
path.enc // THIS IS ENCRYPTED FILE WHICH IS SAVED IN THE GIVEN PATH
"""
```
### Encrypt File Using RSA Warning: Use This For Small Files less than 1024 Bytes
```python
# Deprecated Warning
from Encryptor import RSA_Encryption
cipher = RSA_Encryption(public_file="public_key.pem")
cipher.file_encrypt("pathtofile")
```
### Decrypt File Using RSA
```python
# Deprecated Warning
from Encryptor import RSA_Encryption
cipher = RSA_Encryption(private_file="private_key.pem", public_file="public_key.pem")
cipher.file_decrypt("path.enc")
```
### Decrypt File Using Bush
```python
from Encryptor import Bush_Encryption
cipher = Bush_Encryption("KeyToUse")
cipher.file_decrypt("path.enc")
# Output
# Same File With Removed .enc Extension
```
### Decrypt File Using Fernet
```python
from Encryptor import Fernet_Encryption
cipher = Fernet_Encryption(key='keywhichusedtoencrypt')
cipher.file_decrypt(path='path\to\file.enc')
# output
# Decrypted File will be in the same given path
```

### Decrypt File Using AES
```python
from Encryptor import AES_Encryption
cipher = AES_Encryption(key='keytouse', iv='This is iv 45611')
print(cipher.file_decrypt('path'))
# OUTPUT
"""
File Successfully Decrypted With Given Key
In Case Of any exception:
Something Went Wrong During Decryption Of The File
If nothing went wrong:
path // THIS IS DECRYPTED FILE WHICH IS SAVED IN THE GIVEN PATH
"""
```
### Encrypt String Using Bush
```python
from Encryptor import Bush_Encryption
cipher = Bush_Encryption("keytouse")
cipher.encrypt("Hello, World!")
# Output varies Everytime You Run, Because Of IV Randomization
# b'ZISDJSjdcJmZ1jEtZq-TJ9f_-EK1LYms19_R0G4-Thw=ebOTwrjzmMP2l2kzHtMifQ==ew6pPaBG9QjE_TGD6xyMwA=='
```
### Encrypt String Using RSA
```python
from Encryptor import RSA_Encryption
cipher = RSA_Encryption(public_file="public_key.pem")
cipher.encrypt("Hello, World!")
# Output
# b'{\x7f2\xbe\xa0\xee\x82\xac\x84#\x9b \x12$+\\V\xd5(\xa0\xc1\x11\x19\x9fQ\xacO\x1fJ\xd8XX\xbfR\xe8\xe9Cm\xe0\xd3`\xee\xf0\x7f|Cn\xcf\x00#H\xe2R_\xa4\x19\x1a\x06A\xa2kT\x9dQ'
```
### Encrypt String Using AES
```python
from Encryptor import AES_Encryption
cipher = AES_Encryption(key='keytouse', iv='this is iv 45611')
cipher.encrypt("Hello")
### OUTPUT
# b'}%\x99\x00b3\xb0?\xe5\t\x07wc\xa8\xc6\x8d'
```
### Encrypt String Using Fernet
```python
from Encryptor import Fernet_Encryption
cipher = Fernet_Encryption(key='keytouse')
cipher.encrypt('string')
# Output
# b'gAAAAABg4AFMaGOzEvKpJgArUvJrmhTPLZIio5qAz96PAHs4CWlInKHS-nA48G_2RwQKbHQcDy3fei1ctH5luGSThqkZC520AA=='
```

### Decrypt String Using AES
```python
from Encryptor import AES_Encryption
cipher = AES_Encryption(key='keytouse', iv='this is iv 45611')
cipher.decrypt(b'}%\x99\x00b3\xb0?\xe5\t\x07wc\xa8\xc6\x8d')
### OUTPUT
# 'Hello'
```
### Decrypt String Using Bush
```python
from Encryptor import Bush_Encryption
cipher = Bush_Encryption("keytouse")
cipher.decrypt("data")
# Output
# Decrypted Data
```
### Decrypt String Using RSA
```python
from Encryptor import RSA_Encryption
cipher = RSA_Encryption(public_file="public_key.pem", private_file="private_key.pem")
cipher.decrypt(b'{\x7f2\xbe\xa0\xee\x82\xac\x84#\x9b \x12$+\\V\xd5(\xa0\xc1\x11\x19\x9fQ\xacO\x1fJ\xd8XX\xbfR\xe8\xe9Cm\xe0\xd3`\xee\xf0\x7f|Cn\xcf\x00#H\xe2R_\xa4\x19\x1a\x06A\xa2kT\x9dQ')
# Output
# b'Hello, World!'
```
### Decrypt String Using Fernet
```python
from Encryptor import Fernet_Encryption
cipher = Fernet_Encryption(key='keytouse')
cipher.decrypt(b'gAAAAABg4AFMaGOzEvKpJgArUvJrmhTPLZIio5qAz96PAHs4CWlInKHS-nA48G_2RwQKbHQcDy3fei1ctH5luGSThqkZC520AA==')
# Output
# string
```
### About
```
Hi, I Am Patan Musthakheem I Am The Author Of This Package.
I Created This Tool For Beginners Who Want to encrypt their string or file
using any encryption but they dont know how to use it because 
for beginners it is bit of difficult for using Encryption like AES from scratch.
I Faced Many issues when learning how to encrypt strings and files in python when
when i am beginner i decided to create a very simple tool which will encrypt strings and files
in one line of code.
That day has came, Now you can encrypt and decrypt strings in one line of code.
Thanks To Me.
```