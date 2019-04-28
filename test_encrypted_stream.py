import pytest
import logging
import tempfile

# apparently, the python standard library does not offer a
# convenient function to generate a sequence of pseudo-random bytes
# without unnecessarily using the system's csprng.
# since i don't want to hack together my own thing, we're using numpy.
import numpy.random

# however, we will be generating the key with NaCl's generator
import nacl.utils

from encrypted_stream import EncryptingReader, DecryptingWriter, BLOCKSIZE_v1, OUTPUT_BLOCKSIZE_v1

@pytest.fixture(
    scope="module",
    params=[1, 2**19, 2**20-1, 2**20, 2**20+1, 5 * 2**20 - 1, 5 * 2**20, 5 * 2**20 + 1, 5 * 2**20 + 147]
    )
def source_buffer(request):
    """generates a pseudo-random source buffer in a temporary file"""
    # NOTE: whats a bit annoying here is that the temporary file needs
    # to be writable so we can fill it with random junk, but we
    # actually don't want it to be writable for the tests. this
    # shouldnt _really_ be that problematic, since of course
    # EncryptingReader doesnt try to write to its source, but it might
    # be nice to not have this anyways.

    length = request.param
    
    with tempfile.TemporaryFile() as f:

        random_data = numpy.random.bytes(length)
        f.write(random_data)

        yield f

@pytest.fixture(scope="session")
def key():
    return nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)

def test_zero_length_files(key):
    with pytest.raises(ValueError):
        with tempfile.TemporaryFile() as f:
            EncryptingReader(f, key)


def test_tell_with_sequential_reads(source_buffer, key):

    reader = EncryptingReader(source_buffer, key)
    position = 0

    # make sure that the first few reads stay inside the header
    position += reader.readinto(bytearray(2))
    assert position == reader.tell()

    position += reader.readinto(bytearray(0))
    assert position == reader.tell()

    position += reader.readinto(bytearray(10))
    assert position == reader.tell()

    # this read should get us to byte 24, the end of the header
    position += reader.readinto(bytearray(12))
    assert position == reader.tell()
    assert position == reader.headersize

    # read a bit into the first block
    position += reader.readinto(bytearray(1071))
    assert position == reader.tell()

    # read a bit further
    position += reader.readinto(bytearray(2**18 + 11))
    assert position == reader.tell()

    # do a large read across two block boundaries
    position += reader.readinto(bytearray(2 * 2**20 + 1071))
    assert position == reader.tell()

    # read the rest of the buffer
    while True:
        # one more than the OUTPUT_BLOCKSIZE
        read_bytes = reader.readinto(bytearray(2**20 + 17))
        position += read_bytes
        assert position == reader.tell()

        if read_bytes == 0:
            break

    assert reader.at_source_end


def test_output_size(source_buffer, key):

    reader = EncryptingReader(source_buffer, key)
    while True:
        size = reader.readinto(bytearray(2**20))
        if size == 0:
            break

    assert reader.tell() == reader.output_size
    

# same read order as in test_tell_with_sequential_reads
def test_consistency_with_sequential_reads(source_buffer, key):

    reader = EncryptingReader(source_buffer, key)
    output_array = bytearray(reader.output_size)
    output = memoryview(output_array) # this is necessary to let readinto() assign to slices
    position = 0

    # make sure that the first few reads stay inside the header
    position += reader.readinto(output[position:position+2])
    position += reader.readinto(output[position:position+0])
    position += reader.readinto(output[position:position+10])

    # this read should get us to byte 24, the end of the header
    position += reader.readinto(output[position:position+12])

    # read a bit into the first block
    position += reader.readinto(output[position:position+1071])

    # read a bit further
    position += reader.readinto(output[position:position + 2**18 + 11])

    # do a large read across two block boundaries
    position += reader.readinto(output[position:position + 2 * 2**20 + 1071])

    # read the rest of the buffer
    while True:
        # one more than the OUTPUT_BLOCKSIZE
        read_bytes = reader.readinto(output[position:position + 2**20 + 17])
        position += read_bytes

        if read_bytes == 0:
            break

    # comparison output: read the whole thing at once
    reader.seek(0)
    output_oneread = bytearray(reader.output_size)
    bytes_read = reader.readinto(output_oneread)
    assert bytes_read == reader.output_size
    assert output == output_oneread


def test_consistency_with_seek_SEEK_SET(source_buffer, key, caplog):

    reader = EncryptingReader(source_buffer, key)
    
    # comparison output: read the whole thing at once
    output_oneread = bytearray(reader.output_size)
    bytes_read = reader.readinto(output_oneread)

    seek_locations = [
        0, 1, 2,
        reader.headersize-1,
        reader.headersize,
        reader.headersize+1,
        reader.headersize + 1071,
        reader.headersize + 2**19 + 1,
        reader.headersize + OUTPUT_BLOCKSIZE_v1 - 1,
        reader.headersize + OUTPUT_BLOCKSIZE_v1,
        reader.headersize + OUTPUT_BLOCKSIZE_v1 + 1,
        OUTPUT_BLOCKSIZE_v1 - 1,
        OUTPUT_BLOCKSIZE_v1,
        OUTPUT_BLOCKSIZE_v1 + 1,
        reader.headersize + OUTPUT_BLOCKSIZE_v1 + 1071,
        reader.headersize + OUTPUT_BLOCKSIZE_v1*2 - 1,
        reader.headersize + OUTPUT_BLOCKSIZE_v1*2,
        reader.headersize + OUTPUT_BLOCKSIZE_v1*2 + 1,
        reader.output_size - 4,
        reader.output_size - 1,
        reader.output_size
        ]

    seek_locations = numpy.random.permutation(seek_locations)

    with caplog.at_level(logging.INFO):
        logging.getLogger().info("using randomized seek_locations: {}".format(seek_locations))

    for location in seek_locations:
        reader.seek(location)
        assert reader.tell() == min(location, reader.output_size)
        test_data = bytearray(OUTPUT_BLOCKSIZE_v1 + 2)
        bytes_read = reader.readinto(test_data)

        assert bytes_read == min(len(test_data), max(0, reader.output_size - location))
        assert test_data[:bytes_read] == output_oneread[location:location+bytes_read]

def test_encryption_decryption_roundtrip(source_buffer, key):

    reader = EncryptingReader(source_buffer, key)
    output = bytearray(reader.output_size)
    bytes_read = reader.readinto(output)
    assert bytes_read == len(output)
    reader.close()

    source_length = reader.source_size
    source_buffer.seek(0)
    source_bytes = source_buffer.read(source_length)

    with tempfile.TemporaryFile() as f:
        writer = DecryptingWriter(f, key)
        writer.write(output)
        writer.end_stream()

        length = f.tell()
        f.seek(0)
        comparison_bytes = f.read(length)

        assert source_bytes == comparison_bytes

# TODOs:
# check writer tell()
# check writer stability with sequential reads
# check for nonce reuse in reader (with a mock secretbox)
