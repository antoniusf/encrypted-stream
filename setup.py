import setuptools

with open("README.md", "r") as f:
    long_description = f.read()

setuptools.setup(
    name="encrypted-stream",
    version="0.1.0",
    description="Transparent encryption and decryption for file-like objects",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Antonius Frie",
    author_email="antonius.frie@ruhr-uni-bochum.de",
    url="https://github.com/antoniusf/encrypted-stream",
    license="Apache Software License",

    classifiers=[
        "Development Status :: 3 - Alpha",

        "Topic :: Security :: Cryptography",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
    ],

    install_requires=[
        "pynacl>=1.3",
    ],

    py_modules=["encrypted_stream"],
)
