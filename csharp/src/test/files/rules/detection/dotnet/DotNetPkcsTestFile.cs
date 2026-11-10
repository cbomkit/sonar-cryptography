using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;

public class DotNetPkcsTest {

    private const int Rounds = 600000;

    // --- Pkcs12Builder.SealWithMac: the integrity MAC of a PFX --------------------------------

    public void TestSealWithMac(Pkcs12Builder builder) {
        builder.SealWithMac("password", HashAlgorithmName.SHA256, 100000); // Noncompliant
    }

    public void TestSealWithMacWeak(Pkcs12Builder builder) {
        builder.SealWithMac("password", HashAlgorithmName.SHA1, 2000); // Noncompliant
    }

    public void TestSealWithMacFromConstant(Pkcs12Builder builder) {
        int rounds = Rounds;
        builder.SealWithMac("password", HashAlgorithmName.SHA512, rounds); // Noncompliant
    }

    public void TestSealWithMacNamed(Pkcs12Builder builder) {
        builder.SealWithMac( // Noncompliant
            iterationCount: 50000, hashAlgorithm: HashAlgorithmName.SHA384, password: "password");
    }

    // --- Rfc3161TimestampRequest: the digest of a timestamp request -----------------------------

    public Rfc3161TimestampRequest TestCreateFromData(byte[] data) {
        return Rfc3161TimestampRequest.CreateFromData(data, HashAlgorithmName.SHA256); // Noncompliant
    }

    public Rfc3161TimestampRequest TestCreateFromHash(byte[] hash) {
        return Rfc3161TimestampRequest.CreateFromHash(hash, HashAlgorithmName.SHA384, null, null, true); // Noncompliant
    }

    public Rfc3161TimestampRequest TestCreateFromSignerInfo(SignerInfo signer) {
        return Rfc3161TimestampRequest.CreateFromSignerInfo(signer, HashAlgorithmName.SHA512); // Noncompliant
    }

    // --- the hash and the count are only known to the caller ---------------------------------

    public void TestSealWithMacCountNotKnown(Pkcs12Builder builder, int rounds) {
        builder.SealWithMac("password", HashAlgorithmName.SHA256, rounds); // Noncompliant
    }

    public Rfc3161TimestampRequest TestHashNotKnown(byte[] data, HashAlgorithmName algorithm) {
        return Rfc3161TimestampRequest.CreateFromData(data, algorithm);
    }
}
