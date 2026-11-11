/*
 * OpenSSL's key generation, RSA padding and password-based derivation as C# reaches them.
 *
 * openssl-net declares `RSA_generate_key_ex(IntPtr rsa, int bits, IntPtr e, bn_gencb_st cb)` and
 * calls it with the size as a literal, which is the shape that carries the detail. The 3.x
 * EVP_PKEY_CTX form is the one a new interop layer writes.
 */

using System;
using System.Runtime.InteropServices;

public class OpenSslKeyUsage
{
    private const int RSA_PKCS1_PADDING = 1;
    private const int RSA_NO_PADDING = 3;
    private const int RSA_PKCS1_OAEP_PADDING = 4;
    private const int NID_X9_62_prime256v1 = 415;
    private const int NID_secp384r1 = 715;

    [DllImport("libcrypto")] private static extern int RSA_generate_key_ex(IntPtr rsa, int bits, IntPtr e, IntPtr cb);
    [DllImport("libcrypto")] private static extern int PKCS5_PBKDF2_HMAC(byte[] pass, int passlen, byte[] salt, int saltlen, int iter, IntPtr digest, int keylen, byte[] outKey);

    /* The deprecated-but-ubiquitous RSA key generation. */
    public void GenerateRsa4096(IntPtr rsa, IntPtr e)
    {
        RSA_generate_key_ex(rsa, 4096, e, IntPtr.Zero);
    }

    /* A size that should be flagged. */
    public void GenerateRsa1024(IntPtr rsa, IntPtr e)
    {
        Native.RSA_generate_key_ex(rsa, 1024, e, IntPtr.Zero);
    }

    /* The 0.9.8-deprecated form, where the size is the first argument. */
    public IntPtr GenerateRsaOldest() => Native.RSA_generate_key(2048, 65537, IntPtr.Zero, IntPtr.Zero);

    /* Multi-prime RSA: the size is read, the prime count is not modelled. */
    public void GenerateMultiPrime(IntPtr rsa, IntPtr e)
    {
        Native.RSA_generate_multi_prime_key(rsa, 3072, 3, e, IntPtr.Zero);
    }

    /* The 3.0 one-liner. */
    public IntPtr EvpRsaGen() => Native.EVP_RSA_gen(2048);

    /* The 3.x EVP_PKEY_CTX form. */
    public void CtxRsaBits(IntPtr ctx)
    {
        Native.EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 3072);
    }

    /* DSA and Diffie-Hellman prime lengths. */
    public void DsaAndDh(IntPtr ctx)
    {
        Native.EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, 2048);
        Native.EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx, 2048);
    }

    /* An EC key on P-256, by NID constant resolving to its numeric value. */
    public void EcByNid(IntPtr ctx)
    {
        Native.EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1);
    }

    /* The same with a NID held as a member, which resolves by name. */
    public void EcByNidMember(IntPtr ctx)
    {
        Native.EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, Nid.NID_secp384r1);
    }

    /* The 3.0 way: the curve as a group-name string. */
    public void EcByGroupName(IntPtr ctx)
    {
        Native.EVP_PKEY_CTX_set_group_name(ctx, "P-521");
    }

    /* The 3.0 shorthand, RSA form: the size is the one variadic argument. */
    public IntPtr QuickRsa(IntPtr libctx) => Native.EVP_PKEY_Q_keygen(libctx, null, "RSA", 4096);

    /* The same, EC form, where the variadic argument is a curve name. */
    public IntPtr QuickEc(IntPtr libctx) => Native.EVP_PKEY_Q_keygen(libctx, null, "EC", "P-384");

    /* A parameterless type needs no further argument. */
    public IntPtr QuickEd25519(IntPtr libctx) => Native.EVP_PKEY_Q_keygen(libctx, null, "ED25519");

    /* A post-quantum type. */
    public IntPtr QuickMlDsa(IntPtr libctx) => Native.EVP_PKEY_Q_keygen(libctx, null, "ML-DSA-65");

    /* Every padding constant, by value. */
    public void Paddings(IntPtr ctx)
    {
        Native.EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
        Native.EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
        Native.EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING);
    }

    /* And by name, including the two that have no padding node of their own. */
    public void PaddingsByName(IntPtr ctx)
    {
        Native.EVP_PKEY_CTX_set_rsa_padding(ctx, Rsa.RSA_PKCS1_PSS_PADDING);
        Native.EVP_PKEY_CTX_set_rsa_padding(ctx, Rsa.RSA_X931_PADDING);
    }

    /* The raw RSA primitives, which state the direction as well as the padding. */
    public void RawOperations(byte[] from, byte[] to, IntPtr rsa)
    {
        Native.RSA_public_encrypt(from.Length, from, to, rsa, RSA_PKCS1_OAEP_PADDING);
        Native.RSA_private_decrypt(to.Length, to, from, rsa, RSA_PKCS1_OAEP_PADDING);
        Native.RSA_private_encrypt(from.Length, from, to, rsa, RSA_PKCS1_PADDING);
        Native.RSA_public_decrypt(to.Length, to, from, rsa, RSA_PKCS1_PADDING);
    }

    /* PBKDF2 with a modern iteration count, a 16-byte salt and a 32-byte output. */
    public void Pbkdf2(byte[] pass, byte[] salt, byte[] outKey)
    {
        PKCS5_PBKDF2_HMAC(pass, pass.Length, salt, 16, 600000, Native.EVP_sha256(), 32, outKey);
    }

    /* The SHA-1 shorthand, whose name states the pseudo-random function. */
    public void Pbkdf2Sha1(byte[] pass, byte[] salt, byte[] outKey)
    {
        Native.PKCS5_PBKDF2_HMAC_SHA1(pass, pass.Length, salt, 8, 1000, 20, outKey);
    }

    /* scrypt: the salt and key lengths are read, the cost parameters are not modelled. */
    public void Scrypt(byte[] pass, byte[] salt, byte[] key)
    {
        Native.EVP_PBE_scrypt(pass, pass.Length, salt, 32, 16384, 8, 1, 0, key, 64);
    }

    /* The 3.0 variant with a library context and a property query. */
    public void ScryptEx(IntPtr libctx, byte[] pass, byte[] salt, byte[] key)
    {
        Native.EVP_PBE_scrypt_ex(pass, pass.Length, salt, 32, 16384, 8, 1, 0, key, 64, libctx, null);
    }

    /* A KDF fetched by name. */
    public IntPtr FetchHkdf(IntPtr libctx) => Native.EVP_KDF_fetch(libctx, "HKDF", null);

    public IntPtr FetchPbkdf2(IntPtr libctx) => Native.EVP_KDF_fetch(libctx, "PBKDF2", null);

    /* Counter-check: the key size arrives in a method parameter. */
    public void RsaSizeFromParameter(IntPtr rsa, int bits, IntPtr e)
    {
        Native.RSA_generate_key_ex(rsa, bits, e, IntPtr.Zero);
    }

    /* Counter-check: the iteration count arrives in a method parameter. */
    public void Pbkdf2IterationsFromParameter(byte[] pass, byte[] salt, int iterations, byte[] outKey)
    {
        Native.PKCS5_PBKDF2_HMAC(pass, pass.Length, salt, 16, iterations, Native.EVP_sha256(), 32, outKey);
    }

    /* Counter-check: a NID that is not a curve. */
    public void NotACurveNid(IntPtr ctx)
    {
        Native.EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, 6);
    }

    /* Counter-check: a group name OpenSSL does not have. */
    public void NotACurveName(IntPtr ctx)
    {
        Native.EVP_PKEY_CTX_set_group_name(ctx, "P-128");
    }

    /* Counter-check: a padding constant that is not one. */
    public void NotAPadding(IntPtr ctx)
    {
        Native.EVP_PKEY_CTX_set_rsa_padding(ctx, 42);
    }

    /* Counter-check: a key type EVP_PKEY_Q_keygen does not accept. */
    public IntPtr QuickUnknownType(IntPtr libctx) => Native.EVP_PKEY_Q_keygen(libctx, null, "NTRU", 701);

    /*
     * Counter-check: EVP_PKEY_keygen names neither algorithm nor size -- both were set on the
     * context earlier -- so it is not a rule.
     */
    public void KeygenOnly(IntPtr ctx, IntPtr pkey)
    {
        Native.EVP_PKEY_keygen(ctx, ref pkey);
    }
}
