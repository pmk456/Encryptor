# Py-Encryptor
## What's New
```
* Added New Encryption Class Bush_Encryption
* Added Doc For Every Function
* Added File Encryption
* Many Bugs Fixed
* Upgraded To Version 2.2
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