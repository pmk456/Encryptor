# Author: Patan Musthakheem
# Version: 2.1
# Licence: Apache 2.0
# Please Refer To The https://github.com/pmk456/Encryptor README.md
# Whats New:
# * A New Encryption Method Fernet Added
# * Added File Encryption
# * Many Bugs Fixed
# * Many Exceptions Are Caught Now Under Try Except Blocks
import os
import sys
from base64 import urlsafe_b64encode
from hashlib import sha256


class InvalidKey(ValueError):
    pass


class AES_Encryption:
    """
     The Advanced Encryption Standard (AES) is a symmetric block cipher chosen by the U.S. government to
     protect classified information. AES is implemented in software and hardware throughout the world to
     encrypt sensitive data. It is essential for government computer security, cybersecurity and
     electronic data protection.
     Please Refer To The https://github.com/pmk456/AES-Encryptor README.md
     For Perfectly Using This Package
    """
    try:
        from Crypto.Cipher import AES
    except ImportError:
        print("Pycryptodome Is Not Found On This Computer\n"
              "Please Install using pip [ pip install pycryptodome ]")
        sys.exit(1)

    def __init__(self, key, iv="THIS IS IV 45600", mode=AES.MODE_CBC):
        """
        Constructor For This Class
        :param key: Key Must be string which will used to encrypt the strings or files
        :param iv: initializing vector which is used to randomize the encrypted data, This Must Be 16 Bytes Long,
        default=THIS IS IV 45600
        :param mode: mode for encrypting data, default=MODE_CBC
        """
        if len(iv) < 16 or len(iv) > 16:
            print("Incorrect IV Length (It Must Be 16 Bytes Long)")
            sys.exit(1)
        if not isinstance(key, str):
            print("Key Must Be String")
            sys.exit(1)
        if not isinstance(iv, str):
            print("IV Must Be String")
            sys.exit(1)
        self.key = sha256(key.encode()).digest()
        self.IV = iv.encode()
        self.mode = mode

    @staticmethod
    def __pad(data):
        """
        This Function Is Created For Padding Messages into multiple of 16
        :param data: Data which is not a multiple of 16
        :return: returns encoded string and make it multiple of 16
        """
        while len(data) % 16 != 0:
            data = data + ' '
        return data.encode()

    @staticmethod
    def __file_pad(bin_data):
        """
        This Function is to pad the binary data of the file used For File Encryption
        :param bin_data: Data Which Want to be padded
        :return: Bin data Padded
        """
        while len(bin_data) % 16 != 0:
            bin_data += b'0'
        return bin_data

    def encrypt(self, message):
        """
        Used To Encrypt Strings
        :param message: String Which Want To Be Encrypted
        :return: Encrypted Data Of The String Which Will Be In Bytes
        """
        if not isinstance(message, str):
            raise ValueError('Message Must Be String')
        try:
            cipher = self.AES.new(key=self.key, mode=self.mode, iv=self.IV)
            encrypted_msg = cipher.encrypt(self.__pad(message))
        except Exception:
            raise Exception("Something Went Wrong")
        else:
            return encrypted_msg

    def decrypt(self, data):
        """
        Used To Decrypt Data Given
        :param data: data which is encrypted with the same given key
        :return: Plain string
        """
        if not isinstance(data, bytes):
            raise ValueError('Data Must Be Bytes')
        try:
            cipher = self.AES.new(key=self.key, mode=self.mode, iv=self.IV)
            decrypted_data = cipher.decrypt(data)
        except Exception:
            raise InvalidKey("Data May be Changed")
        else:
            return decrypted_data.decode().rstrip()

    def file_encrypt(self, path: str, return_data: bool = False):
        """
        Used To Encrypt The File
        :param path: Path Of The File Note: If You are using windows please put [ \\ ]
        :param return_data: Returns Encrypted Data If Set To True
        :return: Encrypted File In the same given path with the same name but with extension .enc
        """
        if not os.path.exists(path):
            if sys.platform == 'win32':
                print(r"Note: If You are using windows please put[ \\ ]\n"
                      r"Example: C:\\Windows\\System32\\File.txt")
            raise FileNotFoundError
        try:
            cipher = self.AES.new(key=self.key, mode=self.mode, iv=self.IV)
            with open(path, 'rb') as file:
                data = self.__file_pad(file.read())
                encrypted_data = cipher.encrypt(data)
            new = path + '.enc'
            with open(new, 'wb') as file:
                file.write(encrypted_data)
        except Exception:
            raise Exception('Something Went Wrong During Encryption Of The File Please Use self.Fernet_Encryption For '
                            'Avoiding ERRORS')
        if return_data:
            return encrypted_data

    def file_decrypt(self, path: str, return_data=False) -> bytes:
        """
        Used To Decrypt The File
        :param path: Path Of The File Note: If You are using windows please put [ \\ ]
        Example: C:\\Windows\\System32\\File.txt
        :param return_data: Returns Decrypted Data If Set To True
        :return: Decrypted File With Removed .enc extension In the same given path
        """
        if not isinstance(path, str):
            raise ValueError('Path Must Be String')
        if not os.path.exists(path):
            if sys.platform == 'win32':
                print(r"Note: If You are using windows please put[ \\ ]\n"
                      r"Example: C:\\Windows\\System32\\File.txt")
            raise FileNotFoundError
        try:
            cipher = self.AES.new(key=self.key, mode=self.mode, iv=self.IV)
            with open(path, 'rb') as file:
                data = file.read()
                decrypted_data = cipher.decrypt(data).rstrip(b'0')
            new = path.replace('.enc', '')
            with open(new, 'wb') as file:
                file.write(decrypted_data)
        except Exception:
            raise InvalidKey("Please Check the Key, IV and Data")
        if return_data:
            return decrypted_data


class Fernet_Encryption:
    """
    Depends On cryptography.fernet Package
    self.Fernet is a symmetric encryption method which makes sure that the message encrypted cannot be manipulated/read
    without the key.
    It uses URL safe encoding for the keys.
    self.Fernet also uses 128-bit AES in CBC mode and PKCS7 padding,
    with HMAC using SHA256 for authentication.
    The IV is created from os
    """
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        print("cryptography package Is Not Installed\n"
              "Please Install It using [ pip install cryptography ]")
        Fernet = None
        sys.exit(1)

    def __init__(self, key: str):
        """
        Constructor or Initializer
        :param key: Key To Use
        """
        self.key = urlsafe_b64encode(sha256(key.encode()).digest())

    def encrypt(self, msg: str) -> bytes:
        """
        Encrypt Function To Encrypt Strings
        :param msg: String Which Want To be Encrypted
        :return: Encrypted String Bytes
        """
        if not isinstance(msg, str):
            raise ValueError('This Function Only Accept Strings')
        cipher = self.Fernet(self.key)
        try:
            encrypted_msg = cipher.encrypt(msg.encode())
        except Exception:
            raise Exception("Something Unknown Error")
        return encrypted_msg

    def decrypt(self, data: bytes) -> str:
        """
        Data Which Want To be Decrypted
        :param data: Data Which Is Encrypted
        :return: String Decrypted
        """
        if not isinstance(data, bytes):
            raise ValueError("Data Must Be Bytes")
        cipher = self.Fernet(self.key)
        try:
            decrypted_msg = cipher.decrypt(data)
        except ValueError:
            raise InvalidKey
        return decrypted_msg.decode()

    def file_encrypt(self, path: str, return_data=False) -> bytes:
        """
        Take Path And Returns The Encrypted Binary data of the file
        :param path: Path of the file
        :param return_data: Data Want to be returned or Not
        :return: if return_data is set to True Returns Encrypted Data
        """
        if not isinstance(path, str):
            raise ValueError('Path Must Be A String')
        cipher = self.Fernet(self.key)
        if not os.path.exists(path):
            raise FileNotFoundError('File Not Found Please Check The Path')
        try:
            with open(path, 'rb') as file:
                data = file.read()
        except PermissionError or FileNotFoundError or FileExistsError:
            raise
        name = path + '.enc'
        encrypted_data = cipher.encrypt(data)
        with open(name, 'wb') as file2:
            file2.write(encrypted_data)
        if return_data:
            return encrypted_data

    def file_decrypt(self, path: str, return_data=False):
        """
        :param path: Path of the encrypted file
        :param return_data: if true returns decrypted data
        :return: if return_Data is set to true returns decrypted data
        """
        if not isinstance(path, str):
            raise ValueError('Path Must Be A String')
        cipher = self.Fernet(self.key)
        if not os.path.exists(path):
            raise FileNotFoundError('File Not Found Please Check The Path')
        try:
            with open(path, 'rb') as file:
                data = file.read()
        except PermissionError:
            raise PermissionError
        new = path.replace('.enc', '')
        try:
            decrypted_data = cipher.decrypt(data)
        except Exception:
            raise InvalidKey('Invalid Key Or Data May Be Changed')
        with open(new, 'wb') as file2:
            file2.write(decrypted_data)
        if return_data:
            return decrypted_data
