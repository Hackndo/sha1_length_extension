#!/usr/bin/python
import sha1_appender

print "=> Original sha1"
print sha1_appender.sha1("MySecret!" + "hackndo is amazing")
print "\n=> Appending payload"
print sha1_appender.sha1_append("6861636b6e646f20697320616d617a696e67", "2041", "c187bbe5056dc6602091040b694fffd27e4af1b5", 9, text_format="hex")["injection"]
print "\n=> Predicted sha1"
print sha1_appender.sha1_append("hackndo is amazing", " A", "c187bbe5056dc6602091040b694fffd27e4af1b5", 9)["sha1"]
print "\n=> Check if predicted correct"
print sha1_appender.sha1("MySecret!" + "\x68\x61\x63\x6b\x6e\x64\x6f\x20\x69\x73\x20\x61\x6d\x61\x7a\x69\x6e\x67\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd8\x20\x41")