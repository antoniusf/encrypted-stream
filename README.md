# `encrypted-stream`

[![Documentation Status](https://readthedocs.org/projects/encrypted-stream/badge/?version=latest)](https://encrypted-stream.readthedocs.io/en/latest/?badge=latest) [![Build Status](https://travis-ci.org/antoniusf/encrypted-stream.svg?branch=master)](https://travis-ci.org/antoniusf/encrypted-stream)

**I am taking this project down because I am no longer comfortable with people being able to use crypto that I've written. To be honest, I never expected anyone else to use this. Looking at pypi download numbers, I wasn't even that wrong -- but the thought that other people are relying on this code is still scary. The documenation now contains a notice regarding this, which I've replicated below.**

Hey. I'm sorry if you're looking for the encrypted-stream package. It's no longer here. (Though it's still available as an older version if you really need it.)

I wrote encrypted-stream as a personal project, to encrypt my backups before uploading them to cloud storage, and I pulled all the crypto stuff out into a separate package. The idea was to make everything neat and tidy and well-tested, and I wanted to learn how to make a proper python package.

Implementing your own crypto is traditionally a difficult subject, and there are good reasons for this. It's very easy to make mistakes that make the encryption scheme insecure without breaking things in a noticeable way. I did it anyway, since I couldn't find a pre-existing implementation fulfilling my requirements. I took precautions to limit the level of risk I would incur, and decided that the result was acceptable for my purposes.

And then, after surveying the existing implementations with the same API, and seeing the mistakes they had made, I decided that I couldn't possibly make things worse by publishing mine. I put on some warnings (which, in retrospect, could have been worded more strongly), and expected literally no one to use it. (And, luckily, not many people did.)

A few days ago, I dug the library back out again and realized that I was no longer comfortable with people being able to use the code that I had written. And I checked the download numbers of the package and they were higher than they should have been from only my usage, which means that other people have downloaded this code and used it. Including you, perhaps, if you're reading this. (Hi?)

I have now pulled the release from pypi so that people won't be able to use it anymore. I'm planning to publish a placeholder version in the next few days, just to explain things, once I have figured out how to use pypi again and how best to do that. For now, this notice will have to suffice.

Next steps
----------

If you encrypted data with my library and are now unable to decrypt it, please download the [last full version of the library from my github](https://github.com/antoniusf/encrypted-stream/tree/8357791c8663f8fa7f63cd83f778732e2b91a4db) and install it manually. If you need support doing this, don't hesitate to contact me under antonius.frie (at) ruhr-uni-bochum.de, or here on github.

The library has a known security problem, where incorrect usage can lead to a breakdown of security and enable an adversary to recover the encryption key. The documentation warned about this problem in two places, but (in retrospect) not as prominently as I would have liked. If you used this library to encrypt sensitive data and didn't take this into account, you may contact me (see above) to receive help in determining whether this may have affected you. Ideally, you would reach out to an actually qualified person to work this out with you, but I'm not sure you would have been using this library if you had access to one.
