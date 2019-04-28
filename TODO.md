# TODOs:

- documentation
  - document the expectations `EncryptingReader` has on its base stream (seekable, fixed length, exclusive access: cursor must not be moved externally)
  - write documentation on the file format and explain design choices
  - review the explanatory comments and code for understandability

- implement `tell()` for `DecryptingWriter` (so we can interrupt and resume writing)
- write tests for `DecryptingWriter` stability (and `tell()` correctness) with sequential writes
- make `EncryptingReader` resumable (support for passing nonce into the initializer)
- write tests for resuming writer and reader
  
- clean up the API (visibility of attributes etc.)
- write test against nonce reuse in reader (with a mock secretbox)