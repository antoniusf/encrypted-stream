.. encrypted-stream documentation master file, created by
   sphinx-quickstart on Mon Apr 29 10:55:54 2019.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

encrypted-stream
================

*transparent encryption and decryption for file-like objects*

Say you want to upload a file somewhere, but you'd only like to encrypt it beforehand.

To do this, you could encrypt the entire file at once. You'll need a temporary file to hold the encrypted data, and it needs to be at least as big as your original file. For large files, this would use a lot of extra disk space.

If you don't want to fit the entire file into your RAM at once, you might also want to use a chunking protocol, and you should probably make sure that your cryptographic system is secure and tamper resistant. 

Or, you could just say::

    from encrypted_stream import EncryptingReader

    with open("source", "rb") as source_file:
        encrypted_file = EncryptingReader(source_file, key)

That's it! ``encrypted_file`` will behave just as if you had created a temporary file and stored the encrypted data inside of it, except that it uses no extra disk space and only about 1 MB of your precious RAM.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

.. automodule:: encrypted_stream
   :members:

