Tutorial
========

Encryption
----------

This module works on file-like objects, so let's start by creating a file with some secret message in it. ::

  import tempfile

  with tempfile.NamedTemporaryFile(delete=False) as f:
      f.write(b"secret message")

      # note the file name so we can read from it later
      filename = f.name

If you already have a file you'd like to encrypt, skip this step. Feel free to be more creative with the secret message than I was.

We'll also need to generate a secure random key::

  import encrypted_stream

  key = encrypted_stream.generate_key()

Let's open the file again, for reading. Note that :class:`~encrypted_stream.EncryptingReader` expects a binary stream, so you should open the file in binary mode. Hence, ``"rb"`` instead of just ``"r"``::

  f = open(filename, "rb")
  # TODO: keygen (I think we want to export that as a function...)
  reader = encrypted_stream.EncryptingReader(f, key)

You're now free to read from (and skip around in) your encrypted "file" as you like, but be careful not to touch the source stream ``f``. Doing that would confuse the reader and might produce some not-so-fun bugs.

Let's check how big the encrypted file is, the old fashioned way: by skipping to the end and checking where we land. ::

  import io  # (We'll just need this for the io.SEEK_END constant.)

  size = reader.seek(0, whence=io.SEEK_END)

  # The read position is now at the end of the file, so we'll reset
  # it to the beginning.
  reader.seek(0)

  # though with this class, you can save yourself some trouble and just do
  size = reader.output_size
  
If you used only a short file for testing, you'll see that the encrypted result is quite a bit longer. I can assure you that the extra data will amortize itself over larger files: There's a fixed 24-byte overhead per file, plus an extra 16 bytes for each megabyte of source data. On a 1GiB file, this comes out to about 16kiB, or less than 0.002%. I think this should be acceptable.

Anyway, let's try reading some of that data. In a realistic scenario, you might pass the reader object to another function, maybe to upload it to the cloud or something. Since the reader behaves exactly like a file, you can use it anywhere you'd use a file. Here, though, we'll just read out all of the data. (If you used a really big file for this, like, eats-all-your-RAM big, you should probably pull the data out in chunks instead.) ::

  encrypted_data = reader.readall()

Fantastic! If you look at the result, you'll probably understand nothing, but that's kind of the point. (If the first four bytes look a bit regular to you, that's because those contain the built-in protocol version.)

Finally, let's clean up. Currently, :class:`~encrypted_stream.EncryptingReader` does not close the underlying stream, so we'll need to do that manually::

  reader.close()
  f.close()

Decryption
----------

Let's now try to get that encrypted data back into readable form! Again, we'll need a new temporary file for :class:`~encrypted_stream.DecryptingWriter` to write into. We'll use an unnamed temporary file in the tutorial, but feel free to instead write this into a file of your choice with ``open()``. Remember to use binary mode! ::

  f = tempfile.TemporaryFile()

Then we can instantiate our writer, and write the encrypted data to it::
  
  writer = encrypted_stream.DecryptingWriter(f, key)
  writer.write(encrypted_data)

Note that the writer always keeps an internal buffer of undecrypted bytes, because decryption can only proceed in blocks. That's why we need to call :meth:`~encrypted_stream.DecryptingWriter.end_stream` to tell it that we're done. This will also allow the writer to check if parts of your data are missing. ::

  writer.end_stream()
  
Okay! Let's look at our data. (If you did write this to an actual file, you can also just open that externally.) ::

  # First, we should close the writer. Don't use the underlying stream
  # directly while it is still active!
  writer.close()

  # Then, we'll reset f to its beginning, so we can read the entire contents.
  f.seek(0)

  # the (-1) means that we want to read out the entire stream
  data = f.read(-1)

Tadaa! 🎉

Before using this module in practice, be sure to review the notes in the :doc:`api`, as well as the :doc:`security`.
