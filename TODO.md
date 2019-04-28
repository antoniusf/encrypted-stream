# TODOs:

- reader.seek(): clamp seek position to minimum 0

- documentation
  - document the expectations `EncryptingReader` has on its base stream (seekable, fixed length, exclusive access: cursor must not be moved externally)
  - write documentation on the file format and explain design choices
  - review the explanatory comments and code for understandability

- implement `tell()` for `DecryptingWriter` (so we can interrupt and resume writing)
- write tests for `DecryptingWriter` stability (and `tell()` correctness) with sequential writes
- make `EncryptingReader` resumable (support for passing nonce into the initializer)
- write tests for resuming writer and reader
- rewrite the reader to support 0-length files?
  - my current best idea for how to do this is changing the reader such that the last block is never full (instead of never empty), since this generalizes well to zero-length input. This would mean that for file lengths evenly divisible by the block size, the cursor position at the end of the file would be ambiguous: are we still in the next-to-last block, or already in the last one? so we'd have to introduce an extra flag to distinguish between these cases. i just dislike the idea of introducing extra state and complexity _just_ to handle 0-length files, which most people probably won't use anyway.
  
- clean up the API (visibility of attributes etc.)
- write test against nonce reuse in reader (with a mock secretbox)