/*
 * OpenSSL's symmetric EVP interface as C# reaches it.
 *
 * The shapes are taken from openssl-net (ManagedOpenSsl), the managed wrapper whose Native.cs
 * declares every one of these as a `[DllImport] public extern static` and whose Cipher.cs holds
 * them in static fields:
 *
 *     public static Cipher AES_256_CBC = new Cipher(Native.EVP_aes_256_cbc(), false);
 *     Native.EVP_EncryptInit_ex(ctx, cipher.Handle, IntPtr.Zero, key, iv);
 *
 * Both the qualified form and the bare form a `using static` import produces are covered, because
 * the C# frontend reports an empty receiver for the latter and the holder's name for the former.
 */

using System;
using System.Runtime.InteropServices;

public class OpenSslCipherUsage
{
    // The P/Invoke declarations themselves. A declaration is not a call, so none of these is a
    // detection -- which is what keeps a wrapper's own Native.cs from reporting every algorithm
    // OpenSSL has.
    [DllImport("libcrypto")] private static extern IntPtr EVP_aes_128_cbc();
    [DllImport("libcrypto")] private static extern IntPtr EVP_aes_256_gcm();
    [DllImport("libcrypto")] private static extern int EVP_EncryptInit_ex(IntPtr ctx, IntPtr type, IntPtr impl, byte[] key, byte[] iv);
    [DllImport("libcrypto")] private static extern IntPtr EVP_CIPHER_fetch(IntPtr libctx, string algorithm, string properties);
    [DllImport("libcrypto")] private static extern IntPtr EVP_get_cipherbyname(string name);

    /* The inline shape: the cipher is written as an argument of the call that uses it. */
    public void InlineCipher(IntPtr ctx, byte[] key, byte[] iv)
    {
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), IntPtr.Zero, key, iv);
    }

    /* The qualified shape, which is how a wrapper writes it. */
    public void QualifiedCipher(IntPtr ctx, byte[] key, byte[] iv)
    {
        Native.EVP_EncryptInit_ex(ctx, Native.EVP_aes_128_cbc(), IntPtr.Zero, key, iv);
    }

    /* Held in a local first, the way openssl-net's Cipher class does. */
    public IntPtr HeldInLocal()
    {
        IntPtr cipher = Native.EVP_chacha20_poly1305();
        return cipher;
    }

    /* Three-key Triple DES: the key length is what separates `ede3` from `ede`. */
    public IntPtr TripleDes() => Native.EVP_des_ede3_cbc();

    /* Two-key Triple DES. */
    public IntPtr TwoKeyTripleDes() => Native.EVP_des_ede_cbc();

    /* A stream cipher whose key length OpenSSL lets the caller set later: none is claimed. */
    public IntPtr StreamCipher() => Native.EVP_rc4();

    /* The export-grade variant, whose name does state the key length. */
    public IntPtr ExportStreamCipher() => Native.EVP_rc4_40();

    /* A feedback mode whose width is in the name. */
    public IntPtr NarrowFeedback() => Native.EVP_aes_192_cfb8();

    /* Key wrap, with and without padding. */
    public IntPtr KeyWrap() => Native.EVP_aes_256_wrap();

    /* Single DES in ECB -- no key length, because the name states none. */
    public IntPtr SingleDes() => Native.EVP_des_ecb();

    /* A 3.0 fetch by algorithm name. */
    public IntPtr Fetch(IntPtr libctx) => Native.EVP_CIPHER_fetch(libctx, "AES-256-GCM", null);

    /* The pre-3.0 lookup by name, with OpenSSL's own spelling of Triple DES. */
    public IntPtr ByName() => Native.EVP_get_cipherbyname("DES-EDE3-CBC");

    /* Counter-check: the algorithm name arrives in a method parameter, so none may be invented. */
    public IntPtr FetchFromParameter(IntPtr libctx, string algorithm)
        => Native.EVP_CIPHER_fetch(libctx, algorithm, null);

    /* Counter-check: a string that is not an OpenSSL cipher name. */
    public IntPtr FetchUnknown(IntPtr libctx) => Native.EVP_CIPHER_fetch(libctx, "ROT13-256-CBC", null);

    /* Counter-check: a function OpenSSL does not have. AES-512 does not exist. */
    public IntPtr NotAFunction() => Native.EVP_aes_512_gcm();

    /* Counter-check: EVP_EncryptInit_ex on its own names no algorithm, so it is not a rule. */
    public void InitWithHandle(IntPtr ctx, IntPtr handle, byte[] key, byte[] iv)
    {
        Native.EVP_EncryptInit_ex(ctx, handle, IntPtr.Zero, key, iv);
    }
}
