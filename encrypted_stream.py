# Copyright 2019 Antonius Frie
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import nacl.secret
import struct
import io
from math import floor

BLOCKSIZE_v1 = 2 ** 20
# output blocks always have the extra macbytes
OUTPUT_BLOCKSIZE_v1 = BLOCKSIZE_v1 + nacl.secret.SecretBox.MACBYTES


class EncryptingReader(io.RawIOBase):
    """File-like object that provides a transparently encrypted view
    over another stream.

    .. important:: :class:`EncryptingReader` has a few expectations regarding the source stream:

        - it needs to be seekable
        - it must have a definite and fixed length
        - while the reader is active (not closed), it requires exclusive access to the
          source stream, since the cursor position of the source is used as part of the internal state. Doing seeks, reads, writes, or anything else that will move the source stream's cursor 
          active will likely result in unexpected exceptions (if you're lucky), or corrupt the output stream silently. Additionally, rewriting parts of the source stream -- even if you reset the cursor -- may result in a breakdown of the cryptographic security guarantees provided by this module, if you continue to use the reader afterwards.       

    :param source: The file-like object you want to encrypt. See above for required properties.
    :param key: The key used for encryption, must be a ``bytes`` object of length 32. Generate or derive this key in a secure way.
    """

    # TODO: export nacl key-gen function
    # TODO: add security admonitions for key, nonce (when flexible nonce is added), and re-iterate no-writes on the source stream
    # TODO: add documentation for RawIOBase inherited methods read, readall
    # TODO: call RawIOBase constructor in our constructor? I don't know what that would do, but it might be a good idea

    def __init__(self, source, key):

        self.source = source

        # since encryption happens in blocks, and reads aren't
        # necessarily aligned with block boundaries, we may need to
        # save some data until the next read.
        # initially (while source.tell() == 0), we will be reusing this
        # to contain the secretstream header
        self.remaining_block = bytes()

        # get the size of the source object
        self.source_size = self.source.seek(0, io.SEEK_END)
        # reset the source object to the beginning
        self.source.seek(0)

        if self.source_size == 0:
            raise ValueError("Zero-length file objects are currently unsupported")

        self.secretbox = nacl.secret.SecretBox(key)
        self.file_nonce = nacl.utils.random(20)

        self.remaining_block = self.get_header()
        self.headersize = len(self.remaining_block)

        # use the source size to determine how big the output will be
        # this needs the headersize, that's why we're only computing it now
        self.compute_output_size()

    def get_header(self):

        version_bytes = struct.pack("<HH", 0, 1)
        header = version_bytes + self.file_nonce
        return header

    def get_next_block(self):
        """reads, encrypts, and returns one block starting at the
        current source file position
        """

        # A note on block indices:
        # Internally, we'll use block indices starting at 0, because
        # this simplifies the math. However, the block indices going into
        # the STREAM construction should start at 1, so we'll offset that
        # when interacting with the crypto.

        if self.at_source_end:
            return bytes()

        source_position = self.source.tell()
        assert (source_position % BLOCKSIZE_v1) == 0
        # this is the index of the block we'll encrypt
        block_index = source_position // BLOCKSIZE_v1

        data = self.source.read(BLOCKSIZE_v1)
        if len(data) < BLOCKSIZE_v1:
            # only the last block is allowed to be smaller than blocksize
            assert self.at_source_end

        # construct the nonce
        #  the nonce construction puts a maximum on the block index
        #  (remember that the MSB of the nonce counter is reserved
        #   for the final block marker, that's why we it doesn't say
        #   2**32 here.)
        #  TODO: maybe make this an assert, no one should ever run into this
        if (block_index + 1) >= 2 ** 31:
            raise ValueError("Stream too large; maximum block index surpassed")

        counter = block_index + 1
        # make sure that the flag bit is zero
        assert (counter >> 31) == 0

        if self.at_source_end:
            # this is the last block
            # set the flag bit
            counter |= 1 << 31

        counter = struct.pack("<I", counter)
        nonce = self.file_nonce + counter

        encrypted_block = self.secretbox.encrypt(data, nonce).ciphertext

        return encrypted_block

    @property
    def at_source_end(self):
        return self.source.tell() == self.source_size

    def readable(self):
        return True

    def readinto(self, b):

        # turn the buffer into a memoryview that we know how to operate on,
        # and make sure that we can actually assign bytes to it
        # (taken from python's FileIO.readinto() implementation)
        b = memoryview(b).cast("B")

        # our write position inside of the memoryview, so we can keep
        # track of how much more we need to write
        bytes_written = 0
        length = len(b)

        # first check if we can serve the read from our remaining block
        if length <= len(self.remaining_block):
            b[:] = self.remaining_block[:length]
            self.remaining_block = self.remaining_block[length:]
            return length

        # if we can't, we'll first empty our remaining block, ...
        b[: len(self.remaining_block)] = self.remaining_block[:]
        bytes_written += len(self.remaining_block)
        self.remaining_block = bytes()

        # ... and then keep pushing blocks until the buffer is full.
        # (or until we run out of source data to read)
        while True:

            block = self.get_next_block()

            # is this block enough to fill the buffer?
            left_to_write = length - bytes_written
            if left_to_write <= len(block):
                b[bytes_written:] = block[:left_to_write]
                bytes_written += left_to_write

                self.remaining_block = block[left_to_write:]

                # we just filled the entire buffer
                assert bytes_written == length
                break

            else:
                b[bytes_written : bytes_written + len(block)] = block[:]
                bytes_written += len(block)

                if self.at_source_end:
                    break

        return bytes_written

    def seekable(self):
        return True

    def tell(self):

        source_position = self.source.tell()

        if source_position == 0:
            # we're still in the header
            return self.headersize - len(self.remaining_block)

        elif source_position == self.source_size:  # aka at_source_end
            # we want the index of the last block
            # the integer divide will automatically round down to the
            # beginning of the last block, except if the last block
            # is a full block, in which case it wouldn't do that. The
            # simple fix for this is to subtract 1 before dividing.
            block_index = (self.source_size - 1) // BLOCKSIZE_v1

            block_start = block_index * BLOCKSIZE_v1
            block_size = self.source_size - block_start

        else:
            assert (source_position % BLOCKSIZE_v1) == 0

            # here, again, we'll want to round down to the beginning
            # of the block even though we're at the end. However,
            # since we're not at the end of the file, the blocks are
            # always full, so we'll just subtract 1 from the index.
            #
            # the other way to look at this is that the position is
            # the beginning of the block that will be read next,
            # but the remaining data we've got is still from the
            # previous block, so that's why we need to subtract 1.
            block_index = (source_position // BLOCKSIZE_v1) - 1

            block_size = BLOCKSIZE_v1

        # the size of this output block depends on the size
        # of the corresponding input block
        # (which is usually just BLOCKSIZE_v1, except if we're in the last block)
        output_block_size = block_size + self.secretbox.MACBYTES

        # this output block starts at
        output_block_start = block_index * OUTPUT_BLOCKSIZE_v1

        bytes_read_from_this_block = output_block_size - len(self.remaining_block)
        output_position = output_block_start + bytes_read_from_this_block

        # don't forget that there's still a few bytes of header
        # before the first block starts
        output_position += self.headersize

        return output_position

    def seek(self, offset, whence=io.SEEK_SET):

        if whence == io.SEEK_SET:
            base_point = 0

        elif whence == io.SEEK_CUR:
            base_point = self.tell()

        elif whence == io.SEEK_END:
            base_point = self.output_size

        position = base_point + offset
        del base_point

        # clamp the position
        # this needs to happen before we check if we're still
        # in the header, in case our source_size is zero and
        # the output therefore only consists of the header.
        if position > self.output_size:
            position = self.output_size

        if position < 0:
            position = 0

        if position <= self.headersize:
            # we're still in the header
            # (or at the beginning of the first data block)
            # so the source needs to be at position 0
            self.source.seek(0)

            header = self.get_header()
            self.remaining_block = header[position:]

            return position

        # we're not in the header, so let's offset the position.
        # this way, the first block will start at position 0,
        # which makes things a lot easier
        # (note that since the if above also includes
        #  position == self.headersize, we now have
        #  position >= 1)
        position -= self.headersize

        # compute the block index (this is similar to comparable
        #  code in tell(), so see there why we subtract 1.)
        block_index = (position - 1) // OUTPUT_BLOCKSIZE_v1
        # how many bytes into the block are we?
        # (ie how many bytes would have been read already)
        offset = position - block_index * OUTPUT_BLOCKSIZE_v1

        # where does the corresponding source block start?
        block_start = block_index * BLOCKSIZE_v1
        # go there
        self.source.seek(block_start)
        # and then read in that block
        block = self.get_next_block()

        # finally, set up the remaining_block data
        self.remaining_block = block[offset:]

        return position

    def compute_output_size(self):

        # how many full blocks fit into the output?
        num_full_blocks = floor(self.source_size / BLOCKSIZE_v1)

        # is there anything left over?
        full_blocks_size = num_full_blocks * BLOCKSIZE_v1
        left_over = self.source_size - full_blocks_size

        self.output_size = num_full_blocks * OUTPUT_BLOCKSIZE_v1

        if left_over > 0:
            # we need to account for the last non-full block,
            # which also brings its MAC
            self.output_size += left_over + nacl.secret.SecretBox.MACBYTES

        # don't forget the header!
        self.output_size += self.headersize


class DecryptingWriter(io.RawIOBase):
    """File-like object that transparently decrypts incoming data into an underlying buffer.

    :param sink: The file-like object into which data will be decrypted
    :param key: The key used for decryption
    """

    def __init__(self, sink, key):

        self.sink = sink
        self.secretbox = nacl.secret.SecretBox(key)

        # we need to cache bytes until we've gotten a full block
        self.cache = bytes()

        # while file_nonce is None, we're still in the header
        self.file_nonce = None

        self.stream_complete = False
        self.__closed = False

    def decrypt_block(self, block, block_index, is_last=False):

        counter = block_index + 1
        if counter >= 2 ** 31:
            raise ValueError("Stream too large; maximum block index surpassed")

        if is_last:
            counter |= 1 << 31

        nonce = self.file_nonce + struct.pack("<I", counter)

        return self.secretbox.decrypt(block, nonce)

    def write_block(self, block, known_to_be_last=False):

        self._checkClosed()
        # the header needs to have been decoded before this function can be called
        assert self.file_nonce is not None

        sink_position = self.sink.tell()
        assert (sink_position % BLOCKSIZE_v1) == 0
        # this is the index of the block we'll decrypt
        block_index = sink_position // BLOCKSIZE_v1

        if known_to_be_last:
            try_last = True

        else:
            try:
                data = self.decrypt_block(block, block_index, is_last=False)

            except nacl.exceptions.CryptoError:
                try_last = True

            else:
                # regular decryption was successful!
                try_last = False
                bytes_written = self.sink.write(data)
                assert bytes_written == len(data)

        if try_last:
            try:
                data = self.decrypt_block(block, block_index, is_last=True)
            except nacl.exceptions.CryptoError:
                # something is wrong with the message

                self.decryption_fail()
                raise ValueError(
                    "Failed to decrypt chunk with index {}. This means that your data was either corrupted or has been tampered with. We've gotten rid of the decrypted data that was written so far and closed this stream.".format(
                        block_index
                    )
                )

            else:
                # we've received the last block.
                bytes_written = self.sink.write(data)
                assert bytes_written == len(data)
                self.stream_complete = True
                assert len(self.cache) == 0
                self.close()

        return self.stream_complete

    def decryption_fail(self):

        self.sink.seek(0)
        self.sink.truncate(0)
        self.close()

    def end_stream(self):
        """Call this when you've reached the end of the encrypted source stream. It will ensure that the data you've received is complete and that everything is written to the sink stream, and then close the writer."""

        try:
            if not self.stream_complete:

                if len(self.cache) > 0:
                    # decrypt the last block
                    data = self.cache
                    self.cache = bytes()
                    self.write_block(data, known_to_be_last=True)

                # the stream _has_ to be complete now, otherwise something is missing.
                if not self.stream_complete
                    self.decryption_fail()
                    raise ValueError("stream incomplete")

        finally:
            self.close()

    def close(self):
        """Close the writer. Note that this does not close
        the underlying stream, so you'll have to do that yourself. This allows you to close the stream even if you haven't reached the end, in case you want to pick up where you left of later. If you did reach the end, don't forget to call :py:meth:`end_stream` before you call this method."""

        if not self.__closed:

            try:
                self.flush()

            finally:
                self.__closed = True

    def flush(self):
        self._checkClosed()
        self.sink.flush()

    def readable(self):
        return False

    def writable(self):
        return True

    def write(self, b):

        self._checkClosed()

        self.cache += bytes(b)

        if self.file_nonce is None:
            # we're still in the header
            if len(self.cache) >= 24:  # 4 byte version + 20 byte nonce
                version_major, version_minor = struct.unpack("<HH", self.cache[:4])
                assert version_major == 0
                assert version_minor == 1

                self.file_nonce = self.cache[4:24]
                self.cache = self.cache[24:]

        # pop chunks off of our accumulated cache and decrypt them
        # until we can't anymore
        while len(self.cache) >= OUTPUT_BLOCKSIZE_v1:

            block = self.cache[:OUTPUT_BLOCKSIZE_v1]
            self.cache = self.cache[OUTPUT_BLOCKSIZE_v1:]

            self.write_block(block)

            if self.stream_complete:
                break

        return len(bytes(b))

    def seekable(self):
        """While DecryptingWriter doesn't support seeking, tell() still works"""
        return False

    def tell(self):
        sink_position = self.sink.tell()
        assert (sink_position % BLOCKSIZE_v1) == 0

        if self.file_nonce is None:
            # we're still in the header
            return len(self.cache)

        block_index = sink_position // BLOCKSIZE_v1

        input_position = block_index * OUTPUT_BLOCKSIZE_v1
        # add the header length (24 bytes)
        # TODO: we should really pull this out into a constant somewhere
        input_position += 24
        # we've got these bytes cached, so they were already written to us
        input_position += len(self.cache)

        return input_position
