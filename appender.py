#!/usr/bin/python

import struct, sys, hashlib

def rotate_left(num, bits):
    left = num << bits
    right = num >> (32 - bits)
    return left + right

def padding(msg, size):
    size *= 8
    padding = 64*8 - ((size + 8) % 512) - 64 # +8 because \x80 and -64 because size on 64 bits

    msg += "\x80"

    ret = msg + (padding / 8) * "\x00" + struct.pack(">q", size) # Big endian size
    return ret;

def sha1_custom(msg_padded, h0, h1, h2, h3, h4):
    for j in range(0, len(msg_padded) / 64): # Each 64 bytes chunk depends on the previous one
        chunk = msg_padded[j*64 : (j+1)*64]
        words = {}
        for i in range(0, 16):
            word = chunk[i*4 : (i+1)*4]
            (words[i],) = struct.unpack(">i", word)
        
        # Extend the sixteen 32-bit words into eighty 32-bit words:
        for i in range(16, 80):
            words[i] = rotate_left((words[i-3] ^ words[i-8] ^ words[i-14] ^ words[i-16]) & 0xffffffff, 1)

        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        for i in range(0, 80):
            if 0 <= i <= 19:
                f = d ^ (b & (c ^ d))
                k = 0x5a827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ed9eba1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8f1bbcdc
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xca62c1d6

            a, b, c, d, e = (rotate_left(a, 5) + f + e + k + words[i]) & 0xffffffff, a, rotate_left(b, 30), c, d

        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff
    return (h0, h1, h2, h3, h4)


def sha1(msg):
    return get_hex(sha1_custom(padding(msg, len(msg)), 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0))

def get_hex(s):
    return '%08x%08x%08x%08x%08x' % s

def append_display(known_text, append, hash, secret_size=1):
    res = tuple([int("0x" + hash[i:i+8], 16) for i in range(0, len(hash), 8)])
    print "********************"
    print "* String to inject *"
    print "********************"
    payload = (padding(known_text, len(known_text) + secret_size) + append).encode("hex")
    print '\\x' + '\\x'.join([payload[i:i+2] for i in range(0, len(payload), 2)])
    print "\n********************"
    print "*  Predicted SHA1  *"
    print "********************"
    print get_hex(sha1_custom(padding(append, 64 + len(append)), res[0], res[1], res[2], res[3], res[4]))

def sha1_append(known_text, append, hash, secret_size, text_format="str"):
    if text_format == "hex":
        known_text = known_text.decode("hex")
        append = append.decode("hex")
    res = tuple([int("0x" + hash[i:i+8], 16) for i in range(0, len(hash), 8)])
    payload = (padding(known_text, len(known_text) + secret_size) + append).encode("hex")
    return {"injection": '\\x' + '\\x'.join([payload[i:i+2] for i in range(0, len(payload), 2)]),
        "sha1": get_hex(sha1_custom(padding(append, 64 + len(append)), res[0], res[1], res[2], res[3], res[4]))}

print "Original sha1"
print sha1("MySecret!" + "hackndo is amazing")
print "Appending payload"
print sha1_append("6861636b6e646f20697320616d617a696e67", "2041", "c187bbe5056dc6602091040b694fffd27e4af1b5", 9, text_format="hex")["injection"]
print "Predicted sha1"
print sha1_append("hackndo is amazing", " A", "c187bbe5056dc6602091040b694fffd27e4af1b5", 9)["sha1"]
print "Check if predicted correct"
print sha1("MySecret!" + "\x68\x61\x63\x6b\x6e\x64\x6f\x20\x69\x73\x20\x61\x6d\x61\x7a\x69\x6e\x67\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd8\x20\x41")