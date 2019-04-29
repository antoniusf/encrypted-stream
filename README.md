# `encrypted-stream`

[![Documentation Status](https://readthedocs.org/projects/encrypted-stream/badge/?version=latest)](https://encrypted-stream.readthedocs.io/en/latest/?badge=latest)

This module allows you to wrap an unencrypted file in a special reader class. The reader behaves exactly like a normal file, except that all data you read from it is encrypted. It uses a special encryption protocol which allows it to encrypt almost arbitrarily large files¹ while using no extra disk space and very little RAM (around 1 MB). It even allows you to jump to different locations in the output, which is useful if you're using it to upload a file and need to restart the upload.

There is also a counterpart writer that accepts the encrypted stream and decrypts it into an underlying file.

***

¹ There is a theoretical maximum of a few petabytes of data, but I don't expect anyone to run into this ^^