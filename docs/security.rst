Security considerations
=======================

The current implementation takes the well-tested and hard-to-misuse ``secretbox`` authenticated encryption primitive from NaCl, and combines it with the STREAM encryption protocol from [HR+15]_.

The security of this library therefore depends on three factors:

1. The security of NaCl, and the ``secretbox`` primitive in particular. NaCl is very well respected and generally seen as providing high-quality crypto. This factor is not a concern.
2. The security of the STREAM construction. The paper where it is defined comes with a security proof that reduces it to the security of the underlying authenticated encryption primitive. Also, Phil Rogaway is on the authors list. I don't think this factor is a concern either.
3. The correctness of this implementation. This factor is the problem, because the implementation is written by me.

While I have an interest in cryptography, I am not exactly experienced. I have avoided all of the mistakes I know not to make; I can do nothing about the ones I don't know about. As of yet, no other person has reviewed this implementation.

In many ways, you could probably do worse than using this library. But my recommendation is that you *don't use this library to protect sensitive data*. I simply can't guarantee that it's safe.

.. [HR+15] Hoang V.T., Reyhanitabar R., Rogaway P., Vizár D: Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance. In: Gennaro R., Robshaw M. (eds): *Advances in Cryptology -- CRYPTO 2015.* CRYPTO 2015. Lecture Notes in Computer Science, vol 9215. Springer (2015) [`eprint <https://eprint.iacr.org/2015/189.pdf>`_]
