# Hash length extension for SHA1

Description
===========

Python implementation of **sha1** and **sha1 hash length extension** for [french tutorial on my blog](http://blog.hackndo.com/hash-length-extension/)

How to use
==========

```python
import sha1_extender

print "=> Original sha1"
print sha1_extender.sha1(msg="MySecret!" + "name=hackndo&admin=0")

print "\n=> The magic"
result = sha1_extender.sha1_append(known_text="hackndo is amazing", append=" and smart", hash="c187bbe5056dc6602091040b694fffd27e4af1b5", secret_size=9)
print result["injection"]
print result["sha1"]

print "\n=> Check if predicted is correct"
print sha1_extender.sha1(msg="MySecret!" + "\x68\x61\x63\x6b\x6e\x64\x6f\x20\x69\x73\x20\x61\x6d\x61\x7a\x69\x6e\x67\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd8\x20\x61\x6e\x64\x20\x73\x6d\x61\x72\x74")
```

Result
======
```
=> Original sha1
7cd80684964d9e029c1ba8717a45d54f14b15fcb

=> The magic
\x68\x61\x63\x6b\x6e\x64\x6f\x20\x69\x73\x20\x61\x6d\x61\x7a\x69\x6e\x67\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd8\x20\x61\x6e\x64\x20\x73\x6d\x61\x72\x74
8288af4b63cd05aa7d7b9d8ea553a1d0d08e2b10

=> Check if predicted is correct
8288af4b63cd05aa7d7b9d8ea553a1d0d08e2b10
```
