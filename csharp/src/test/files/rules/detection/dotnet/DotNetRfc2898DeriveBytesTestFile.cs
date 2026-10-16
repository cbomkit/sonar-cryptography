using System;
using System.Security.Cryptography;

public class DotNetRfc2898DeriveBytesTest {

    private const int Iterations = 210000;
    private const int DerivedKeyBytes = 32;
    private static readonly byte[] FixedSalt = new byte[16];

    // --- constructor, full four-parameter form -----------------------------------------------

    public void TestPbkdf2() {
        var kdf = new Rfc2898DeriveBytes("password", new byte[16], 10000, HashAlgorithmName.SHA256); // Noncompliant
    }

    // --- constructor, arity three: no hash, so .NET defaults to SHA-1 ------------------------

    public void TestPbkdf2NoHash() {
        var kdf = new Rfc2898DeriveBytes("password", new byte[8], 1000); // Noncompliant
    }

    // --- constructor, arity two ---------------------------------------------------------------

    public void TestPbkdf2SaltOnly() {
        var kdf = new Rfc2898DeriveBytes("password", new byte[32]); // Noncompliant
    }

    // --- constructor, the int saltSize overload rather than a byte[] salt ---------------------

    public void TestPbkdf2SaltSize() {
        var kdf = new Rfc2898DeriveBytes("password", 24, 5000, HashAlgorithmName.SHA512); // Noncompliant
    }

    // --- constructor, values coming from const fields and locals -----------------------------

    public void TestPbkdf2FromConstants() {
        int rounds = Iterations;
        var kdf = new Rfc2898DeriveBytes("password", FixedSalt, rounds, HashAlgorithmName.SHA384); // Noncompliant
    }

    // --- constructor, keyword arguments in a different order than declared -------------------

    public void TestPbkdf2NamedReordered() {
        var kdf = new Rfc2898DeriveBytes(
            "password", hashAlgorithm: HashAlgorithmName.SHA256, iterations: 100000, salt: new byte[16]); // Noncompliant
    }

    // --- static Pbkdf2, layout (password, salt, iterations, hashAlgorithm, outputLength) -----

    public void TestPbkdf2StaticByteArray() {
        byte[] key = Rfc2898DeriveBytes.Pbkdf2(
            new byte[8], new byte[16], 10000, HashAlgorithmName.SHA256, 32); // Noncompliant
    }

    public void TestPbkdf2StaticString() {
        byte[] key = Rfc2898DeriveBytes.Pbkdf2(
            "password", FixedSalt, Iterations, HashAlgorithmName.SHA256, DerivedKeyBytes); // Noncompliant
    }

    // --- static Pbkdf2, layout (password, salt, destination, iterations, hashAlgorithm) ------
    // Same arity, different order. iterations and hashAlgorithm must still land on the right
    // parameters, and outputLength must stay absent rather than be filled from iterations.

    public void TestPbkdf2StaticSpanDestination() {
        Span<byte> destination = stackalloc byte[48];
        Rfc2898DeriveBytes.Pbkdf2(
            "password", FixedSalt, destination, 150000, HashAlgorithmName.SHA384); // Noncompliant
    }

    // --- instance operations ------------------------------------------------------------------

    public void TestPbkdf2GetBytes() {
        var kdf = new Rfc2898DeriveBytes("password", new byte[16], 10000, HashAlgorithmName.SHA256); // Noncompliant
        byte[] derived = kdf.GetBytes(32);
    }

    public void TestPbkdf2CryptDeriveKey() {
        var kdf = new Rfc2898DeriveBytes("password", new byte[16], 10000, HashAlgorithmName.SHA256); // Noncompliant
        byte[] iv = new byte[8];
        byte[] key = kdf.CryptDeriveKey("TripleDES", "SHA1", 192, iv);
    }

    // --- negative cases: the algorithm must still be found, the values must stay absent -------

    // Iteration count arrives as a method parameter with differing call sites, so it is unknowable.
    public void TestPbkdf2UnknownIterations(int rounds) {
        var kdf = new Rfc2898DeriveBytes("password", new byte[16], rounds, HashAlgorithmName.SHA256); // Noncompliant
    }

    public void CallUnknownIterationsOnce() {
        TestPbkdf2UnknownIterations(1000);
    }

    public void CallUnknownIterationsTwice() {
        TestPbkdf2UnknownIterations(2000);
    }

    // Salt comes from a call this engine cannot see into, so no salt length may be reported.
    public void TestPbkdf2UnknownSalt() {
        byte[] salt = LoadSaltFromConfiguration();
        var kdf = new Rfc2898DeriveBytes("password", salt, 30000, HashAlgorithmName.SHA256); // Noncompliant
    }

    private byte[] LoadSaltFromConfiguration() {
        return Convert.FromBase64String(Environment.GetEnvironmentVariable("SALT"));
    }
}
