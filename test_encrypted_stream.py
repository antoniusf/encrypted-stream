import pytest
import logging
import tempfile
import io

# apparently, the python standard library does not offer a
# convenient function to generate a sequence of pseudo-random bytes
# without unnecessarily using the system's csprng.
# since i don't want to hack together my own thing, we're using numpy.
import numpy.random

# however, we will be generating the key with NaCl's generator
import nacl.utils

from encrypted_stream import (
    generate_key,
    EncryptingReader,
    DecryptingWriter,
    BLOCKSIZE_v1,
    OUTPUT_BLOCKSIZE_v1,
)


@pytest.fixture
def sequential_check_increments():
    # TODO: check that we land on the header/block 0 boundary
    # TODO: maybe land on a later block boundary as well
    # TODO: maybe add some more zero increments, just for fun
    def generate():
        yield 2  # make sure that the first few positions are inside the header
        yield 0
        yield 10
        yield 12  # this should land us directly at the end of the header
        yield 1071  # go a bit into the first block
        yield 2 ** 18 + 11  # go a bit further, but stay in the first block
        yield 2 * 2 ** 20 + 1071  # do a big operation across two block boundaries

        while True:
            yield OUTPUT_BLOCKSIZE_v1 + 1

    return generate()


@pytest.fixture(
    scope="module",
    params=[
        1,
        2 ** 19,
        2 ** 20 - 1,
        2 ** 20,
        2 ** 20 + 1,
        5 * 2 ** 20 - 1,
        5 * 2 ** 20,
        5 * 2 ** 20 + 1,
        5 * 2 ** 20 + 147,
    ],
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


@pytest.fixture(scope="module")
def encrypted_bytes(source_buffer, key):

    reader = EncryptingReader(source_buffer, key)
    output = bytearray(reader.output_size)
    bytes_read = reader.readinto(output)
    assert bytes_read == len(output)
    reader.close()

    return output


def test_generate_key():

    key = generate_key()

    # we can't actually test the randomness aspect here,
    # so we'll just check that it has the right format
    assert type(key) == bytes
    assert len(key) == nacl.secret.SecretBox.KEY_SIZE


@pytest.fixture(scope="session")
def key():
    return generate_key()


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
    position += reader.readinto(bytearray(2 ** 18 + 11))
    assert position == reader.tell()

    # do a large read across two block boundaries
    position += reader.readinto(bytearray(2 * 2 ** 20 + 1071))
    assert position == reader.tell()

    # read the rest of the buffer
    while True:
        # one more than the OUTPUT_BLOCKSIZE
        read_bytes = reader.readinto(bytearray(2 ** 20 + 17))
        position += read_bytes
        assert position == reader.tell()

        if read_bytes == 0:
            break

    assert reader.at_source_end


def test_output_size(source_buffer, key):

    reader = EncryptingReader(source_buffer, key)
    while True:
        size = reader.readinto(bytearray(2 ** 20))
        if size == 0:
            break

    assert reader.tell() == reader.output_size


# same read order as in test_tell_with_sequential_reads
def test_consistency_with_sequential_reads(source_buffer, key):

    reader = EncryptingReader(source_buffer, key)
    output_array = bytearray(reader.output_size)
    output = memoryview(
        output_array
    )  # this is necessary to let readinto() assign to slices
    position = 0

    # make sure that the first few reads stay inside the header
    position += reader.readinto(output[position : position + 2])
    position += reader.readinto(output[position : position + 0])
    position += reader.readinto(output[position : position + 10])

    # this read should get us to byte 24, the end of the header
    position += reader.readinto(output[position : position + 12])

    # read a bit into the first block
    position += reader.readinto(output[position : position + 1071])

    # read a bit further
    position += reader.readinto(output[position : position + 2 ** 18 + 11])

    # do a large read across two block boundaries
    position += reader.readinto(output[position : position + 2 * 2 ** 20 + 1071])

    # read the rest of the buffer
    while True:
        # one more than the OUTPUT_BLOCKSIZE
        read_bytes = reader.readinto(output[position : position + 2 ** 20 + 17])
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
        0,
        1,
        2,
        reader.headersize - 1,
        reader.headersize,
        reader.headersize + 1,
        reader.headersize + 1071,
        reader.headersize + 2 ** 19 + 1,
        reader.headersize + OUTPUT_BLOCKSIZE_v1 - 1,
        reader.headersize + OUTPUT_BLOCKSIZE_v1,
        reader.headersize + OUTPUT_BLOCKSIZE_v1 + 1,
        OUTPUT_BLOCKSIZE_v1 - 1,
        OUTPUT_BLOCKSIZE_v1,
        OUTPUT_BLOCKSIZE_v1 + 1,
        reader.headersize + OUTPUT_BLOCKSIZE_v1 + 1071,
        reader.headersize + OUTPUT_BLOCKSIZE_v1 * 2 - 1,
        reader.headersize + OUTPUT_BLOCKSIZE_v1 * 2,
        reader.headersize + OUTPUT_BLOCKSIZE_v1 * 2 + 1,
        reader.output_size - 4,
        reader.output_size - 1,
        reader.output_size,
    ]

    seek_locations = numpy.random.permutation(seek_locations)

    with caplog.at_level(logging.INFO):
        logging.getLogger().info(
            "using randomized seek_locations: {}".format(seek_locations)
        )

    for location in seek_locations:
        reader.seek(location)
        assert reader.tell() == min(location, reader.output_size)
        test_data = bytearray(OUTPUT_BLOCKSIZE_v1 + 2)
        bytes_read = reader.readinto(test_data)

        assert bytes_read == min(len(test_data), max(0, reader.output_size - location))
        assert (
            test_data[:bytes_read] == output_oneread[location : location + bytes_read]
        )


def test_consistency_with_seek_SEEK_END(source_buffer, key, encrypted_bytes):

    reader = EncryptingReader(source_buffer, key)
    comparison = reader.read(reader.output_size)
    assert len(comparison) == reader.output_size
    reader.seek(0)

    # subtract 1 in case the last block is full, so that we're always
    # guaranteed to round down to the beginning of the block
    last_block_index = (reader.output_size - 1) // OUTPUT_BLOCKSIZE_v1
    last_block_start = last_block_index * OUTPUT_BLOCKSIZE_v1
    last_block_length = reader.output_size - last_block_start

    offsets = [
        -1,
        -2,
        -1071,
        -last_block_length + 1,
        -last_block_length,
        -last_block_length - 1,
        -last_block_length - 1071,
        -last_block_length - OUTPUT_BLOCKSIZE_v1 + 1,
        -last_block_length - OUTPUT_BLOCKSIZE_v1,
        -last_block_length - OUTPUT_BLOCKSIZE_v1 - 1,
    ]

    for offset in offsets:
        reader.seek(offset, io.SEEK_END)
        # read to the end
        output = reader.read(-offset)
        assert reader.tell() == reader.output_size

        # since offset is negative, we'll use python's built-in backward indexing to check
        assert comparison[offset:] == output


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


def test_tell_with_sequential_writes(encrypted_bytes, key, sequential_check_increments):

    with tempfile.TemporaryFile() as f:
        writer = DecryptingWriter(f, key)

        position = 0
        for inc in sequential_check_increments:
            writer.write(encrypted_bytes[position : position + inc])
            position += inc
            assert min(position, len(encrypted_bytes)) == writer.tell()

            if writer.stream_complete:
                break

            if position > len(encrypted_bytes):
                writer.end_stream()
                break


def test_consistency_with_sequential_writes(
    source_buffer, encrypted_bytes, key, sequential_check_increments
):

    source_size = source_buffer.seek(0, io.SEEK_END)
    source_buffer.seek(0)
    comparison = source_buffer.read(source_size)

    with tempfile.TemporaryFile() as f:
        writer = DecryptingWriter(f, key)

        position = 0
        for inc in sequential_check_increments:
            writer.write(encrypted_bytes[position : position + inc])
            position += inc

            if writer.stream_complete:
                break

            if position > len(encrypted_bytes):
                writer.end_stream()
                break

        writer.close()

        length = f.tell()
        f.seek(0)
        output = f.read(length)

        assert comparison == output


# this returns the blocks separately, because it is important to ensure that the reordering tests actually swap whole blocks. otherwise, decryption fails trivially because the ciphertext is just broken.
@pytest.fixture(scope="module")
def three_encrypted_blocks(key):

    with tempfile.TemporaryFile() as f:

        random_data = numpy.random.bytes(3 * BLOCKSIZE_v1)
        f.write(random_data)

        reader = EncryptingReader(f, key)
        header = reader.read(24)
        # make sure that we are on a block boundary:
        # remaining_block should be empty
        assert len(reader.remaining_block) == 0

        first_block = reader.read(OUTPUT_BLOCKSIZE_v1)
        assert len(reader.remaining_block) == 0

        second_block = reader.read(OUTPUT_BLOCKSIZE_v1)
        assert len(reader.remaining_block) == 0

        third_block = reader.read(OUTPUT_BLOCKSIZE_v1)
        assert len(reader.remaining_block) == 0

    return (header, first_block, second_block, third_block)


def test_decryption_fail_truncation(three_encrypted_blocks, key):

    header, first_block, second_block, third_block = three_encrypted_blocks

    with tempfile.TemporaryFile() as f:

        writer = DecryptingWriter(f, key)

        writer.write(header)
        writer.write(first_block)

        # TODO: make a more specific exception class
        with pytest.raises(ValueError):
            writer.end_stream()


def test_decryption_fail_advanced_truncation(three_encrypted_blocks, key):
    """Some intermediary blocks are missing, but the final block is still present"""

    header, first_block, second_block, third_block = three_encrypted_blocks

    with tempfile.TemporaryFile() as f:

        writer = DecryptingWriter(f, key)

        writer.write(header)
        writer.write(first_block)

        with pytest.raises(ValueError):
            writer.write(third_block)
            writer.end_stream()


# we'll only want to test one specific message length here, because we can only re-order with more than 3 blocks. using the parametrized fixture for this would be wasteful, though it _would_ be nice if we could reuse that code.
def test_decryption_fail_reordering(three_encrypted_blocks, key):

    header, first_block, second_block, third_block = three_encrypted_blocks

    with tempfile.TemporaryFile() as f:

        writer = DecryptingWriter(f, key)

        writer.write(header)

        with pytest.raises(ValueError):
            writer.write(second_block)
            writer.write(first_block)
            writer.write(third_block)
            writer.end_stream()


def test_reader_attributes(key):

    with tempfile.TemporaryFile() as f:

        # 0-length files are unsupported...
        f.write(bytes(1))
        reader = EncryptingReader(f, key)

        assert reader.readable() == True
        assert reader.seekable() == True
        assert reader.writable() == False


def test_writer_attributes(key):

    with tempfile.TemporaryFile() as f:
        writer = DecryptingWriter(f, key)

        assert writer.readable() == False
        assert writer.seekable() == False
        assert writer.writable() == True
