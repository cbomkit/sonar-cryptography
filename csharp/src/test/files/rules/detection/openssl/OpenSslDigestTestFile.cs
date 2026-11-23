/*
 * OpenSSL's digests and HMAC as C# reaches them.
 *
 * openssl-net's MessageDigest.cs holds every digest the same way it holds the ciphers --
 * `public static MessageDigest SHA256 = new MessageDigest(Native.EVP_sha256(), false);` -- and its
 * HMAC.cs calls `Native.HMAC(digest.Handle, key, key.Length, data, data.Length, hash, ref len)`
 * with the digest as a field access, which is exactly the shape that cannot be resolved and must
 * therefore leave the HMAC component without a digest rather than guess one.
 */

using System;
using System.Runtime.InteropServices;

public class OpenSslDigestUsage
{
    [DllImport("libcrypto")] private static extern IntPtr EVP_sha256();
    [DllImport("libcrypto")] private static extern int EVP_DigestInit_ex(IntPtr ctx, IntPtr type, IntPtr impl);

    /* The inline shape. */
    public void InlineDigest(IntPtr ctx)
    {
        EVP_DigestInit_ex(ctx, EVP_sha256(), IntPtr.Zero);
    }

    public IntPtr Sha1() => Native.EVP_sha1();

    public IntPtr Sha384() => Native.EVP_sha384();

    public IntPtr Sha3() => Native.EVP_sha3_256();

    public IntPtr Shake() => Native.EVP_shake256();

    public IntPtr Md5() => Native.EVP_md5();

    public IntPtr Blake2() => Native.EVP_blake2b512();

    public IntPtr Sm3() => Native.EVP_sm3();

    public IntPtr Ripemd() => Native.EVP_ripemd160();

    /* A 3.0 fetch by name, in the provider's own spelling. */
    public IntPtr Fetch(IntPtr libctx) => Native.EVP_MD_fetch(libctx, "SHA2-512", null);

    /* The pre-3.0 lookup by name. */
    public IntPtr ByName() => Native.EVP_get_digestbyname("SHA256");

    /* The one-shot HMAC: a keyed MAC happens here, and the digest is a handle we cannot read. */
    public void OneShotHmac(IntPtr md, byte[] key, byte[] data, byte[] hash, ref uint len)
    {
        Native.HMAC(md, key, key.Length, data, data.Length, hash, ref len);
    }

    /* The streaming form, deprecated in 3.0 and still the common one. */
    public void StreamingHmac(IntPtr ctx, byte[] key, IntPtr md)
    {
        Native.HMAC_Init_ex(ctx, key, key.Length, md, IntPtr.Zero);
    }

    /* The 1.1.0-deprecated four-argument form. */
    public void OldStreamingHmac(IntPtr ctx, byte[] key, IntPtr md)
    {
        Native.HMAC_Init(ctx, key, key.Length, md);
    }

    /* Counter-check: a digest OpenSSL does not have. */
    public IntPtr NotADigest() => Native.EVP_sha2_384();

    /* Counter-check: a name that is not a digest. */
    public IntPtr FetchUnknown(IntPtr libctx) => Native.EVP_MD_fetch(libctx, "SNEFRU-256", null);

    /* Counter-check: the name arrives in a parameter. */
    public IntPtr FetchFromParameter(IntPtr libctx, string name) => Native.EVP_MD_fetch(libctx, name, null);

    /*
     * Counter-check: EVP_md5_sha1 is the concatenated TLS 1.0/1.1 handshake hash. It is not one
     * digest and has no model, so it is deliberately absent from the table and reports nothing.
     */
    public IntPtr ConcatenatedHash() => Native.EVP_md5_sha1();

    /* Counter-check: EVP_DigestInit_ex names no algorithm of its own. */
    public void InitWithHandle(IntPtr ctx, IntPtr md)
    {
        Native.EVP_DigestInit_ex(ctx, md, IntPtr.Zero);
    }

    /* --- EVP_MAC_fetch: the only place OpenSSL names a MAC by string. --------------------- */

    public IntPtr Hmac() => Native.EVP_MAC_fetch(IntPtr.Zero, "HMAC", null);

    public IntPtr Cmac() => Native.EVP_MAC_fetch(IntPtr.Zero, "CMAC", null);

    public IntPtr Kmac128() => Native.EVP_MAC_fetch(IntPtr.Zero, "KMAC-128", null);

    /* The hyphenless spelling OpenSSL also accepts. */
    public IntPtr Kmac256() => Native.EVP_MAC_fetch(IntPtr.Zero, "KMAC256", null);

    /* Lower case: OpenSSL's fetch is case-insensitive, so this is the same MAC. */
    public IntPtr Poly() => Native.EVP_MAC_fetch(IntPtr.Zero, "poly1305", null);

    public IntPtr Sip() => Native.EVP_MAC_fetch(IntPtr.Zero, "SipHash", null);

    /*
     * Counter-check: GMAC is AES-GCM used as a MAC. The mapper has GMAC only as a cipher mode, so
     * there is no algorithm node for it -- and naming it AES would state an encryption that is not
     * happening.
     */
    public IntPtr Gmac() => Native.EVP_MAC_fetch(IntPtr.Zero, "GMAC", null);

    /*
     * Counter-check: BLAKE2BMAC is a keyed MAC. The mapper has BLAKE2b as a message digest, and
     * reporting that would say the code hashes where it authenticates.
     */
    public IntPtr Blake2bMac() => Native.EVP_MAC_fetch(IntPtr.Zero, "BLAKE2BMAC", null);

    /* Counter-check: a MAC that does not exist. */
    public IntPtr Invented() => Native.EVP_MAC_fetch(IntPtr.Zero, "ROT13MAC", null);

    /* Counter-check: the name arrives in a parameter. */
    public IntPtr MacFromParameter(string name) => Native.EVP_MAC_fetch(IntPtr.Zero, name, null);
}
