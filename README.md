# Py-Encryptor
## What's New
```
* Added New Enccryption Class Fernet_Encryption
* Added File Encryption
* Added Doc For Every Function
* Many Bugs Fixed
* Many Exceptions Catched Under Try Except
```
## Installation
```
pip install AES-Encryptor
```
## Using git
```
git clone https://github.com/pmk456/Encryptor
cd Encryptor
python setup.py install
```
## Usage
### Encrypt File Using Fernet (RECOMMENDED)
```
From Encryptor import Fernet_Encryption
cipher = Fernet_Encryption(key='keytouse')
cipher.encrypt(path)
# Output
Encrypted File with Extension .enc will be In The Same Path
```
### Encrypt File Using AES (NOT RECOMMENDED)
```
from Encryptor import AES_Encryption
cipher = AES_Encryption(key='keytouse', iv='this is iv 45611')
print(cipher.file_encrypt(path))
### Output
File Successfully Encrypted With Given Key
In Case Of any exception:
Something Went Wrong During Encryption Of The File
path.enc // THIS IS ENCRYPTED FILE WHICH IS SAVED IN THE GIVEN PATH
```
### Decrypt File Using Fernet
```
from Encryptor import Fernet_Encryption
cipher = Fernet_Encryption(key='keywhichusedtoencrypt')
cipher.file_decrypt(path='path\to\file.enc')
# output
Decrypted File will be in the same given path
```

### Decrypt File Using AES
```
from Encryptor import AES_Encryption
cipher = AES_Encryption(key='keytouse', iv='This is iv 45611')
print(cipher.file_decrypt(path))
### OUTPUT
File Successfully Decrypted With Given Key
In Case Of any exception:
Something Went Wrong During Decryption Of The File
If nothing went wrong:
path // THIS IS DECRYPTED FILE WHICH IS SAVED IN THE GIVEN PATH
```
### Encrypt String Using AES
```
from Encryptor import AES_Encryption
cipher = AES_Encryption(key='keytouse', iv='this is iv 45611')
cipher.encrypt("Hello")
### OUTPUT
b'}%\x99\x00b3\xb0?\xe5\t\x07wc\xa8\xc6\x8d'
```
### Encrypt String Using Fernet
```
from Encryptor import Fernet_Encryption
cipher = Fernet_Encryption(key='keytouse')
cipher.encrypt('string')
# Output
b'gAAAAABg4AFMaGOzEvKpJgArUvJrmhTPLZIio5qAz96PAHs4CWlInKHS-nA48G_2RwQKbHQcDy3fei1ctH5luGSThqkZC520AA=='
```

### Decrypt String Using AES
```
from Encryptor import AES_Encryption
cipher = AES_Encryption(key='keytouse', iv='this is iv 45611')
cipher.decrypt(b'}%\x99\x00b3\xb0?\xe5\t\x07wc\xa8\xc6\x8d')
### OUTPUT
'Hello'
```
### Decrypt String Using Fernet
```
from Encryptor import Fernet_Encryption
cipher = Fernet_Encryption(key='keytouse')
cipher.decrypt(b'gAAAAABg4AFMaGOzEvKpJgArUvJrmhTPLZIio5qAz96PAHs4CWlInKHS-nA48G_2RwQKbHQcDy3fei1ctH5luGSThqkZC520AA==')
# Output
string
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