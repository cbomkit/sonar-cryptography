using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;

public class DotNetCoseTest {

    // --- the RSA overload: key, signaturePadding, hashAlgorithm -------------------------------

    public CoseSigner TestRsaPss(RSA rsa) {
        return new CoseSigner(rsa, RSASignaturePadding.Pss, HashAlgorithmName.SHA256); // Noncompliant
    }

    public CoseSigner TestRsaPkcs1(RSA rsa) {
        return new CoseSigner(rsa, RSASignaturePadding.Pkcs1, HashAlgorithmName.SHA384); // Noncompliant
    }

    // --- the overload for ECDSA and other keys: key, hashAlgorithm ----------------------------

    public CoseSigner TestEcdsa(ECDsa ecdsa) {
        return new CoseSigner(ecdsa, HashAlgorithmName.SHA256); // Noncompliant
    }

    // --- with header maps ----------------------------------------------------------------------

    public CoseSigner TestRsaWithHeaders(RSA rsa, CoseHeaderMap protectedHeaders) {
        return new CoseSigner(rsa, RSASignaturePadding.Pss, HashAlgorithmName.SHA512, protectedHeaders); // Noncompliant
    }

    public CoseSigner TestEcdsaWithHeaders(ECDsa ecdsa, CoseHeaderMap protectedHeaders, CoseHeaderMap unprotectedHeaders) {
        return new CoseSigner(ecdsa, HashAlgorithmName.SHA384, protectedHeaders, unprotectedHeaders); // Noncompliant
    }

    // --- a weak hash is reported as written ---------------------------------------------------

    public CoseSigner TestWeakHash(RSA rsa) {
        return new CoseSigner(rsa, RSASignaturePadding.Pkcs1, HashAlgorithmName.SHA1); // Noncompliant
    }

    // --- keyword arguments out of declared order -----------------------------------------------

    public CoseSigner TestNamedReordered(RSA rsa) {
        return new CoseSigner( // Noncompliant
            hashAlgorithm: HashAlgorithmName.SHA256, signaturePadding: RSASignaturePadding.Pss, key: rsa);
    }

    // --- the hash is only known to the caller: the padding is reported, the hash is absent ----

    public CoseSigner TestHashNotKnown(RSA rsa, HashAlgorithmName hash) {
        return new CoseSigner(rsa, RSASignaturePadding.Pss, hash); // Noncompliant
    }
}
