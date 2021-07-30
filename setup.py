import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()
setuptools.setup(
    name='Py-Encryptor',
    version='2.3',
    description="Encrypt Strings And Files With Bush Encryption (OR) AES Encryption (OR) Fernet Encryption",
    long_description=long_description,
    long_description_content_type='text/markdown',
    url="https://github.com/pmk456/Encryptor",
    author="Patan Musthakheem",
    author_email="patanmusthakheem786@gmail.com",
    license="Apache 2.0",
    classifiers=[
        'License :: OSI Approved :: Apache Software License',
    ],
    keywords=[
        'encryption',
        'encryptors',
        'aes',
        'bush'
    ],
    project_urls={
        'Documentation': 'https://github.com/pmk456/Encryptor/blob/main/README.md',
        'Source': 'https://github.com/pmk456/Encryptor',
        'Tracker': 'https://github.com/pmk456/Encryptor/issues'
    },
    install_requires=[
        'pycryptodome >= 3.9.6',
        'cryptography >= 3.4.7',
        'Bush-Encryption >= 0.3',
        'rsa >= 4.7.2'
    ],
    python_requires=">=3.5",
    package_dir={"": "src"},
    packages=setuptools.find_packages(where="src")
)
