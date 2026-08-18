from Crypto.Hash import MD5

hash_md5 = MD5.new() # Noncompliant {{(MessageDigest) MD5}}
