# TODOs:

- documentation
  - document the expectations `EncryptingReader` has on its base stream (seekable, fixed length, exclusive access: cursor must not be moved externally)
  - write documentation on the file format and explain design choices
  - review the explanatory comments and code for understandability

- protection against re-writing misuse:
  - I think we should just go for a nonce-misuse resistant encryption scheme; this is the most obvious and least hacky approach. `miscreant` offers an implementation of AES-SIV in python, and it even implements the STREAM construction, which would mean that I don't have to touch crypto code at all 🎉
    (maybe not though, since miscreant's base implementation does not support seeking, so I might have to manually set the counters in there or something. Point of dislike for this approach: We'd have some coupled state to keep in sync (source file pos + miscreant encryptor counter), which I don't like because I feel that it introduces unnecessary complexity and potential for state mismatch problems.

- close source streams when the views are closed? This would make the context manager function really useful, so you could just write

    with EncryptingReader(open("source", "rb")) as f:

  etc.

- make `EncryptingReader` resumable (support for passing nonce into the initializer)
- write tests for resuming writer and reader
- rewrite the reader to support 0-length files?
  - my current best idea for how to do this is changing the reader such that the last block is never full (instead of never empty), since this generalizes well to zero-length input. This would mean that for file lengths evenly divisible by the block size, the cursor position at the end of the file would be ambiguous: are we still in the next-to-last block, or already in the last one? so we'd have to introduce an extra flag to distinguish between these cases. i just dislike the idea of introducing extra state and complexity _just_ to handle 0-length files, which most people probably won't use anyway.
  
- clean up the API (visibility of attributes etc.)
- write test against nonce reuse in reader (with a mock secretbox)