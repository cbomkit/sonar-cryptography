/*
 * Comprehensive test file for System.Security.Cryptography ECDiffieHellman (ECDH)
 * detection rules.
 *
 * Covers all three ECDiffieHellman-related classes and their complete operational API surface:
 *   - ECDiffieHellman (abstract base)
 *   - ECDiffieHellmanCng, ECDiffieHellmanOpenSsl (derived from ECDiffieHellman)
 *
 * Architecture note: all methods inherited from ECDiffieHellman / AsymmetricAlgorithm
 * (KeySize, DeriveKeyMaterial, DeriveKeyFromHash, DeriveKeyFromHmac, DeriveKeyTls,
 * DeriveRawSecretAgreement) are covered once here. The detection engine tracks the variable
 * and fires the same depending rules for every concrete ECDiffieHellman subclass.
 *
 * Known gap: the PublicKey property cannot be detected at all (see DotNetECDiffieHellman.java
 * class javadoc for the full, verified explanation) — no test attempts it.
 */

using System.Security.Cryptography;

public class DotNetECDiffieHellmanTest
{
    // -------------------------------------------------------------------------
    // Section 1: Factory methods / constructors
    // -------------------------------------------------------------------------

    public void TestECDHCreate()
    {
        var ecdh = ECDiffieHellman.Create();
    }

    public void TestECDHCreateWithCurve()
    {
        var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
    }

    public void TestECDHCng()
    {
        var ecdh = new ECDiffieHellmanCng();
    }

    public void TestECDHOpenSsl()
    {
        var ecdh = new ECDiffieHellmanOpenSsl();
    }

    // -------------------------------------------------------------------------
    // Section 2: Property setters (via assignment → synthetic set_X invocations)
    // -------------------------------------------------------------------------

    public void TestPropertyKeySize256()
    {
        var ecdh = ECDiffieHellman.Create();
        ecdh.KeySize = 256;
    }

    public void TestPropertyKeySize384()
    {
        var ecdh = ECDiffieHellman.Create();
        ecdh.KeySize = 384;
    }

    // -------------------------------------------------------------------------
    // Section 3: Key-derivation operations
    // -------------------------------------------------------------------------

    public void TestDeriveKeyMaterial()
    {
        var ecdh = ECDiffieHellman.Create();
        ECDiffieHellmanPublicKey otherPartyKey = null;
        byte[] keyMaterial = ecdh.DeriveKeyMaterial(otherPartyKey);
    }

    public void TestDeriveKeyFromHash()
    {
        var ecdh = ECDiffieHellman.Create();
        ECDiffieHellmanPublicKey otherPartyKey = null;
        byte[] keyMaterial = ecdh.DeriveKeyFromHash(otherPartyKey, HashAlgorithmName.SHA256);
    }

    public void TestDeriveKeyFromHmac()
    {
        var ecdh = ECDiffieHellman.Create();
        ECDiffieHellmanPublicKey otherPartyKey = null;
        byte[] hmacKey = new byte[32];
        byte[] keyMaterial = ecdh.DeriveKeyFromHmac(otherPartyKey, HashAlgorithmName.SHA256, hmacKey);
    }

    public void TestDeriveKeyTls()
    {
        var ecdh = ECDiffieHellman.Create();
        ECDiffieHellmanPublicKey otherPartyKey = null;
        byte[] prfLabel = new byte[16];
        byte[] prfSeed = new byte[32];
        byte[] keyMaterial = ecdh.DeriveKeyTls(otherPartyKey, prfLabel, prfSeed);
    }

    public void TestDeriveRawSecretAgreement()
    {
        var ecdh = ECDiffieHellman.Create();
        ECDiffieHellmanPublicKey otherPartyKey = null;
        byte[] secret = ecdh.DeriveRawSecretAgreement(otherPartyKey);
    }

    // -------------------------------------------------------------------------
    // Section 4: Combined usage patterns (real-world scenarios)
    // Demonstrates that depending rules fire correctly for ALL derived classes.
    // -------------------------------------------------------------------------

    public void TestECDHCngFullFlow()
    {
        var ecdh = new ECDiffieHellmanCng();
        ecdh.KeySize = 384;
        ECDiffieHellmanPublicKey otherPartyKey = null;
        byte[] keyMaterial = ecdh.DeriveKeyMaterial(otherPartyKey);
    }

    public void TestECDHOpenSslDeriveFlow()
    {
        var ecdh = new ECDiffieHellmanOpenSsl();
        ECDiffieHellmanPublicKey otherPartyKey = null;
        byte[] keyMaterial = ecdh.DeriveKeyFromHash(otherPartyKey, HashAlgorithmName.SHA256);
    }
}
