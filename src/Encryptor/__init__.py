# Author: Patan Musthakheem
# Version: 2.3
# Licence: Apache 2.0
# Please Refer To The https://github.com/pmk456/Encryptor README.md
# Whats New:
# * A New Encryption Method Bush Encryption, RSA Encryption Added
# * Many Bugs Fixed
# * Added File Encryption
# * Many Exceptions Are Caught Now Under Try Except Blocks
# * Upgraded To Version 2.3
import os
import rsa
import sys
from base64 import urlsafe_b64encode
from hashlib import sha256
from Crypto.Cipher import AES
from bush import Bush
from cryptography.fernet import Fernet
from .enc import EncBP


class InvalidKey(ValueError):
    pass


class FileError(Exception):
    pass


class PrivateKeyNotFound(ValueError):
    pass


class VerificationFailed(Exception):
    pass


class Bush_Encryption(EncBP):
    """
    This Algorithm is inspired From Fernet which uses AES
    The Encrypted Cipher Text changes every time you run the code
    because of change in IV (Initializing Vector) Which is generated from
    OS and it is embedded in the cipher text as well!
    And It uses Sha256 for making sure that the data is not altered in any manners
    And the Sha256 Digest is also embedded in the cipher text as well.
    Which Makes This Algorithm A Bit Different From Other Algorithms
    """

    def __init__(self, key):
        """
        Constructor
        :param key: Key To use
        """
        self.key = key
        if not isinstance(key, bytes):
            self.key = key.encode()

    def encrypt(self, message) -> bytes:
        """
        To Encrypt Strings
        :param message: Message Which Want to Encrypted
        :return: Bytes With Encrypted Message
        """
        if not isinstance(message, bytes):
            message = message.encode()
        cipher = Bush(self.key)
        return cipher.encrypt(message)

    def decrypt(self, data: bytes) -> str:
        """
        To Decrypt Strings
        :param data: Data Which Is Encrypted
        :return: String Decrypted
        """
        if not isinstance(data, bytes):
            raise ValueError("Data Must Be Bytes")
        cipher = Bush(self.key)
        return cipher.decrypt(data).rstrip()

    def file_encrypt(self, path: str, return_data: bool = False) -> bytes:
        """
        :param path: Path of the file
        :param return_data: If true return encrypted data
        :return None
        """
        if not os.path.exists(path):
            raise FileNotFoundError("File Not Found Please Check The Path")
        with open(path, "rb") as file:
            data = file.read()
        pass
        encrypted_data = self.encrypt(data)
        new = path + '.enc'
        try:
            with open(new, 'wb') as file:
                file.write(encrypted_data)
        except (PermissionError, FileExistsError):
            raise FileError
        if return_data:
            return encrypted_data

    def file_decrypt(self, path: str, return_data: bool = False):
        """
        Used To Decrypt Files
        :param path: Path Of The File with .enc Extension
        :param return_data: if true returns decrypted data
        :return: None
        """
        if not os.path.exists(path):
            raise FileNotFoundError("File Not Found Please Check The Path")
        if not path.endswith('.enc'):
            raise FileError("File Doesn't Contain .enc Extension")
        try:
            with open(path, 'rb') as file:
                data = file.read()
            dec_data = self.decrypt(data)
            new = path.replace(".enc", "")
            with open(new, 'wb') as file:
                file.write(dec_data)
        except (FileExistsError, PermissionError, ValueError):
            raise FileError("Something Wrong With The File Permissions")
        if return_data:
            return dec_data


class AES_Encryption(EncBP):
    """
     The Advanced Encryption Standard (AES) is a symmetric block cipher chosen by the U.S. government to
     protect classified information. AES is implemented in software and hardware throughout the world to
     encrypt sensitive data. It is essential for government computer security, cybersecurity and
     electronic data protection.
     Please Refer To The https://github.com/pmk456/AES-Encryptor README.md
     For Perfectly Using This Package
    """

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
        self.AES = AES

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
                print("Note: If You are using windows please put[ \\\\ ]\n"
                      "Example: C:\\\\Windows\\\\System32\\\\File.txt")
            raise FileNotFoundError("File Not Found Please Check The Path")
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
                print("Note: If You are using windows please put[ \\\\ ]\n"
                      "Example: C:\\\\Windows\\\\System32\\\\File.txt")
            raise FileNotFoundError("File Not Found Please Check The Path")
        if not path.endswith('.enc'):
            raise ValueError("File Doesn't Contain .enc Extension")
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


class Fernet_Encryption(EncBP):
    """
    Depends On cryptography.fernet Package
    self.Fernet is a symmetric encryption method which makes sure that the message encrypted cannot be manipulated/read
    without the key.
    It uses URL safe encoding for the keys.
    self.Fernet also uses 128-bit AES in CBC mode and PKCS7 padding,
    with HMAC using SHA256 for authentication.
    The IV is created from os
    """

    def __init__(self, key: str):
        """
        Constructor or Initializer
        :param key: Key To Use
        """
        self.key = urlsafe_b64encode(sha256(key.encode()).digest())
        self.Fernet = Fernet

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
            raise InvalidKey("Please Check The Key")
        return decrypted_msg.decode()

    def file_encrypt(self, path: str, return_data=False) -> bytes:
        """
        Take Path And Returns The Encrypted Binary data of the file
        :param path: Path of the file
        :param return_data: Data Want to be returned or Not
        :return: if return_data is set to True Returns Encrypted Data
        """
        if not isinstance(path, str):
            raise FileError('Path Must Be A String')
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
        if not os.path.exists(path):
            raise FileNotFoundError('File Not Found Please Check The Path')
        if not isinstance(path, str):
            raise ValueError('Path Must Be A String')
        if not path.endswith('.enc'):
            raise FileError("File Doesn't Contain .enc Extension")
        cipher = self.Fernet(self.key)
        try:
            with open(path, 'rb') as file:
                data = file.read()
        except PermissionError:
            raise
        new = path.replace('.enc', '')
        try:
            decrypted_data = cipher.decrypt(data)
        except Exception:
            raise InvalidKey('Invalid Key Or Data May Be Changed')
        with open(new, 'wb') as file2:
            file2.write(decrypted_data)
        if return_data:
            return decrypted_data


class RSA_Encryption(EncBP):
    """
    ASymmetric Encryption
    RSA (Rivest–Shamir–Adleman) is a public-key cryptology that is widely used for secure data transmission.
    It is also one of the oldest, a public-key cryptology, the encryption key is public and distinct from the
    decryption key, which is kept secret (private). An RSA user creates and publishes a public key based on two large
    prime numbers, along with an auxiliary value. The prime numbers are kept secret. Messages can be encrypted by anyone
    , via the public key, but can only be decoded by someone who have the private Key
    """

    def __init__(self, public_file: str, private_file: str = None, generate_keys=False, key_size=512):
        self.private_file = private_file
        if private_file is not None:
            if not os.path.exists(private_file):
                raise FileNotFoundError("File Not Found Please Check The Path")
            try:
                with open(private_file, "rb") as file:
                    self.private_key = rsa.PrivateKey.load_pkcs1(file.read())
            except(ValueError, Exception):
                raise Exception("Not A Valid Private Key File")
        self.public_file = public_file
        if key_size != 512 and generate_keys:
            if key_size < 15:
                raise ValueError("Key_size Is Too Short")
            self.generate_keys(key_size)
        try:
            with open(public_file, "rb") as file:
                data = file.read()
                self.public_key = rsa.PublicKey.load_pkcs1(data)
        except(ValueError, Exception):
            raise

    def encrypt(self, message: str) -> bytes:
        if not isinstance(message, str):
            raise ValueError("Message Must Be String")
        try:
            return rsa.encrypt(message.encode(), self.public_key)
        except(ValueError, Exception):
            raise Exception("Something Went Wrong During Encryption")

    def decrypt(self, data: bytes) -> str:
        if self.private_file is None:
            raise PrivateKeyNotFound("Please Instantiate This Class With Private Key\n"
                                     "Private Key Not Found")
        if not isinstance(data, bytes):
            raise ValueError("Data Must Be Bytes")
        try:
            return rsa.decrypt(data, self.private_key)
        except(ValueError, Exception):
            raise Exception("Something Went Wrong During Decryption")

    def file_encrypt(self, path: str, return_data: bool = False) -> bytes:  # Don't use For larger Files (Deprecated)
        if not isinstance(path, str):
            raise ValueError("Path Must Be String")
        if not os.path.exists(path):
            raise FileNotFoundError("File Not Found Please Check The Path")
        try:
            with open(path, "rb") as file:
                data = file.read()
        except (PermissionError, Exception, OverflowError):
            # OverFlow Error Will Be Raised When Data Is Too Large To Fit In Padded Block
            raise
        enc_data: bytes = rsa.encrypt(data, self.public_key)
        new = path + '.enc'
        try:
            with open(new, "wb") as file:
                file.write(enc_data)
        except(PermissionError, FileExistsError):
            raise
        if return_data:
            return enc_data

    def file_decrypt(self, path: str, return_data: bool = False) -> bytes:  # (Deprecated)
        if self.private_file is None:
            raise PrivateKeyNotFound("Please Instantiate This Class With Private Key\n"
                                     "Private Key Not Found")
        if not isinstance(path, str):
            raise ValueError("Path Must Be String")
        if not path.endswith('.enc'):
            raise FileError("File Doesn't Contain .enc Extension")
        with open(path, "rb") as file:
            try:
                dec_data = rsa.decrypt(file.read(), self.private_key)
            except(ValueError, Exception):
                raise
        try:
            with open(path.replace(".enc", ""), "wb") as file:
                file.write(dec_data)
        except(ValueError, Exception):
            raise FileError("Something Wrong With File Permissions")
        if return_data:
            return dec_data

    def sign(self, data: bytes, algo: str = "SHA-1"):
        """
        :param data: Data Which Want To Sign
        :param algo: the hash method to use on the data. Use 'MD5', 'SHA-1',
        'SHA-224', SHA-256', 'SHA-384' or 'SHA-512'
        :return: Signature Of The Data
        """
        if self.private_file is None:
            raise PrivateKeyNotFound("Please Instantiate The Class With Private Key")
        supported_algos = ['SHA-1', 'SHA-224', 'SHA-256', 'SHA-384', 'SHA-512', "MD5"]
        if algo not in supported_algos:
            raise ValueError('Not A Valid Hashing Algorithm\n'
                             f'Use {" | ".join(supported_algos)}')
        return rsa.sign(data, self.private_key, algo)

    def verify_signature(self, data: bytes, signature_data: bytes):
        """
        :param data: Data To Check
        :param signature_data: Signature of Data Which is Signed With RSA
        :return: True if data is correct else False
        """
        if not isinstance(signature_data, bytes):
            raise ValueError("Signature Data Must Be Bytes")
        if not isinstance(data, bytes):
            raise ValueError("Data Must Be Bytes")
        try:
            check = rsa.verify(data, signature_data, pub_key=self.public_key)
        except (ValueError, Exception):
            return False
        return True, check

    def sign_file(self, path: str, algo: str = "SHA-1"):
        if not isinstance(path, str):
            raise ValueError("Path Must Be String")
        if not os.path.exists(path):
            raise FileNotFoundError("File Not Found Please Check The Path")
        try:
            with open(path, "rb") as file:
                data = file.read()
        except(FileNotFoundError, PermissionError):
            raise
        return self.sign(data=data, algo=algo)

    def verify_file(self, path: str, signature_data: bytes):
        """
        :param path: Path Of The File
        :param signature_data: Signed Digest
        :return: True if data is correct else False
        """
        if not isinstance(path, str):
            raise ValueError("Path Must Be String")
        try:
            with open(path, "rb") as file:
                data = file.read()
        except(FileNotFoundError, PermissionError):
            raise
        return self.verify_signature(data, signature_data)

    @classmethod
    def generate_keys(cls, size: int = 512) -> None:
        public, private = rsa.newkeys(size)
        pri_file = open("private_key.pem", "wb")
        pub_file = open("public_key.pem", "wb")
        pri_file.write(private.save_pkcs1())
        pub_file.write(public.save_pkcs1())
        return
