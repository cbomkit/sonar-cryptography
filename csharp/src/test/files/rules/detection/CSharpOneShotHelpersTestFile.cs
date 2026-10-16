/*
 * The static one-shot hashing and MAC helpers. Since .NET 5 these are the recommended way to hash,
 * and they have no creation step, so a file can use them and contain no Create call at all. In the
 * local corpus that was the case in 8 of the 14 files that use one, which is why these need rules
 * of their own rather than being treated as operations on an already-detected object.
 */

using System;
using System.Security.Cryptography;

public class CSharpOneShotHelpers
{
    public byte[] Sha256(byte[] d) => SHA256.HashData(d);
    public byte[] Sha384(byte[] d) => SHA384.HashData(d);
    public byte[] Sha512(byte[] d) => SHA512.HashData(d);
    public byte[] Sha1(byte[] d) => SHA1.HashData(d);
    public byte[] Md5(byte[] d) => MD5.HashData(d);

    // TryHashData, the span-destination form of the same call.
    public bool TrySha256(byte[] d, Span<byte> dest) => SHA256.TryHashData(d, dest, out int w);

    // HMAC one-shots. The key length is read where the call states it as an array.
    public byte[] HmacSha256Literal(byte[] d) => HMACSHA256.HashData(new byte[32], d);

    // The same call with a key the engine cannot measure: the MAC must still be reported and the
    // key length must stay absent.
    public byte[] HmacSha512Unknown(byte[] d)
    {
        byte[] key = Convert.FromBase64String(Environment.GetEnvironmentVariable("K"));
        return HMACSHA512.HashData(key, d);
    }
}
