/*
 * Comprehensive test file for System.Security.Cryptography X25519DiffieHellman (X25519)
 * detection rules.
 *
 * Covers all three X25519DiffieHellman-related classes and their complete verified operational
 * API surface:
 *   - X25519DiffieHellman (abstract base) — entry point is the static GenerateKey() factory
 *     (there is no Create() method, unlike ECDiffieHellman)
 *   - X25519DiffieHellmanCng, X25519DiffieHellmanOpenSsl (derived from X25519DiffieHellman)
 *
 * Architecture note: DeriveRawSecretAgreement is the only key-agreement operation that exists on
 * X25519DiffieHellman (verified against the official Microsoft Learn API reference — no
 * DeriveKeyMaterial/DeriveKeyFromHash/DeriveKeyFromHmac/DeriveKeyTls, and no settable KeySize
 * property, unlike ECDiffieHellman). See DotNetX25519DiffieHellman.java class javadoc for the
 * full, verified rationale.
 *
 * Known gap: reading/exporting the public key (e.g. ExportPublicKey()) cannot be meaningfully
 * modeled as a depending rule (see DotNetX25519DiffieHellman.java class javadoc) — no test
 * attempts it.
 */

using System.Security.Cryptography;

public class DotNetX25519DiffieHellmanTest
{
    // -------------------------------------------------------------------------
    // Section 1: Factory method / constructors
    // -------------------------------------------------------------------------

    public void TestX25519GenerateKey()
    {
        var x25519 = X25519DiffieHellman.GenerateKey();
    }

    public void TestX25519Cng()
    {
        CngKey cngKey = null;
        var x25519 = new X25519DiffieHellmanCng(cngKey);
    }

    public void TestX25519OpenSsl()
    {
        SafeEvpPKeyHandle handle = null;
        var x25519 = new X25519DiffieHellmanOpenSsl(handle);
    }

    // -------------------------------------------------------------------------
    // Section 2: DeriveRawSecretAgreement operation (all overloads collapse to one rule)
    // -------------------------------------------------------------------------

    public void TestDeriveRawSecretAgreementByteArray()
    {
        var x25519 = X25519DiffieHellman.GenerateKey();
        byte[] otherPartyPublicKey = new byte[32];
        byte[] secret = x25519.DeriveRawSecretAgreement(otherPartyPublicKey);
    }

    public void TestDeriveRawSecretAgreementOtherParty()
    {
        var x25519 = X25519DiffieHellman.GenerateKey();
        var otherParty = X25519DiffieHellman.GenerateKey();
        byte[] secret = x25519.DeriveRawSecretAgreement(otherParty);
    }

    // -------------------------------------------------------------------------
    // Section 3: Combined usage patterns (real-world scenarios)
    // Demonstrates that the depending rule fires correctly for ALL derived classes.
    // -------------------------------------------------------------------------

    public void TestX25519CngDeriveFlow()
    {
        CngKey cngKey = null;
        var x25519 = new X25519DiffieHellmanCng(cngKey);
        byte[] otherPartyPublicKey = new byte[32];
        byte[] secret = x25519.DeriveRawSecretAgreement(otherPartyPublicKey);
    }

    public void TestX25519OpenSslDeriveFlow()
    {
        SafeEvpPKeyHandle handle = null;
        var x25519 = new X25519DiffieHellmanOpenSsl(handle);
        byte[] otherPartyPublicKey = new byte[32];
        byte[] secret = x25519.DeriveRawSecretAgreement(otherPartyPublicKey);
    }
}
