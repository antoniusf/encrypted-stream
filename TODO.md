# TODOs:

- documentation
  - document the expectations `EncryptingReader` has on its base stream (seekable, fixed length, exclusive access: cursor must not be moved externally)
  - write documentation on the file format and explain design choices
  - review the explanatory comments and code for understandability

- file format: add a 4-byte (or smth) block-wise nonce to protect against re-writing misuse
  - 4 bytes is really *really* not enough for a nonce, but if it's only meant to protect from a case that shouldn't happen anyways, maybe that's ok?
  - since we can't cache, we'd have to compute the nonce from the data
  - what i dislike about this is that it's a really kinda half-baked solution
  - i also don't want to use more than 4 bytes for this feature since we're trading these off for the length (and security) of the file nonce...
  - can we extend the XSalsa20 nonce further?
    - this is icky too because it's going way too much in the direction of "rolling your own crypto"
    - might negatively affect security of the overall system
  - im *reaaaally* tempted by threefish's long block sizes right now
    - also not a nice solution, b/c a) threefish is not as well analyzed as either aes or salsa
    - and b) we'd still have to go to uncomfortably low levels of crypto (manually doing message authentication etc.)

- close source streams when the views are closed? This would make the context manager function really useful, so you could just write

    with EncryptingReader(open("source", "rb")) as f:

  etc.

- make `EncryptingReader` resumable (support for passing nonce into the initializer)
- write tests for resuming writer and reader
- rewrite the reader to support 0-length files?
  - my current best idea for how to do this is changing the reader such that the last block is never full (instead of never empty), since this generalizes well to zero-length input. This would mean that for file lengths evenly divisible by the block size, the cursor position at the end of the file would be ambiguous: are we still in the next-to-last block, or already in the last one? so we'd have to introduce an extra flag to distinguish between these cases. i just dislike the idea of introducing extra state and complexity _just_ to handle 0-length files, which most people probably won't use anyway.
  
- clean up the API (visibility of attributes etc.)
- write test against nonce reuse in reader (with a mock secretbox)