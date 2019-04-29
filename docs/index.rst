.. encrypted-stream documentation master file, created by
   sphinx-quickstart on Mon Apr 29 10:55:54 2019.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

encrypted-stream
================

*transparent encryption and decryption for file-like objects*

.. warning:: This is a very early release! Some parts of the code are not tested yet, some are in need of improvement. The documetation is incomplete. There may be cryptographically relevant bugs. Things may break without warning!

Say you want to upload a file somewhere, but you'd like to encrypt it beforehand.

To do this, you could encrypt the entire file at once. You'll need a temporary file to hold the encrypted data, and it needs to be at least as big as your original file. For large files, this would use a lot of extra disk space.

If you don't want to fit the entire file into your RAM at once, you might also want to use a chunking encryption protocol, and you should probably make sure that your cryptographic system is secure and tamper resistant. 

Or, you could just say::

    from encrypted_stream import EncryptingReader

    with open("source", "rb") as source_file:
        encrypted_file = EncryptingReader(source_file, key)

That's it! ``encrypted_file`` will behave just as if you had created a temporary file and stored the encrypted data inside of it, except that it uses no extra disk space and only about 1 MB of your precious RAM.

There's also a matching :class:`~encrypted_stream.DecryptingWriter` that works the same way: Write encrypted data to it, and it writes the decrypted result into the file you give it.

Contents
--------

.. toctree::
   :maxdepth: 2

   api

