/*
 * Comprehensive test file for RandomNumberGenerator / RNGCryptoServiceProvider detection rules
 * (DotNetRandomNumberGenerator.java).
 *
 * Covers:
 *   - RandomNumberGenerator.Create() / Create(string) + instance GetBytes/GetNonZeroBytes
 *     (including their Span<byte> overloads, which are virtual instance methods, not static --
 *     confirmed by compiling this exact file against the real .NET 10 compiler)
 *   - RandomNumberGenerator's genuinely static-only methods: Fill, GetBytes(int),
 *     GetHexString, GetInt32, GetItems, GetString, Shuffle
 *   - RNGCryptoServiceProvider constructor overloads + instance GetBytes/GetNonZeroBytes
 *
 * Note: GetNonZeroBytes has NO static overload at all (unlike GetBytes, which has a genuinely
 * static GetBytes(int) alongside its instance overloads) -- `RandomNumberGenerator.GetNonZeroBytes(data)`
 * does not compile (CS0120). There is therefore no "static GetNonZeroBytes" test case in this file;
 * TestCreateAndGetNonZeroBytes below already exercises the (only) instance form.
 */

using System.Security.Cryptography;

public class DotNetRandomNumberGeneratorTest
{
    // -------------------------------------------------------------------------
    // Section 1: RandomNumberGenerator.Create() / Create(string) + instance operations
    // -------------------------------------------------------------------------

    public void TestCreateAndGetBytes()
    {
        RandomNumberGenerator rng = RandomNumberGenerator.Create();
        byte[] data = new byte[32];
        rng.GetBytes(data);
    }

    public void TestCreateAndGetNonZeroBytes()
    {
        RandomNumberGenerator rng = RandomNumberGenerator.Create();
        byte[] data = new byte[32];
        rng.GetNonZeroBytes(data);
    }

    public void TestCreateNamed()
    {
        RandomNumberGenerator rng = RandomNumberGenerator.Create("RandomNumberGenerator");
        byte[] data = new byte[32];
        rng.GetBytes(data);
    }

    // -------------------------------------------------------------------------
    // Section 2: RandomNumberGenerator static-only methods
    // -------------------------------------------------------------------------

    public void TestStaticFill()
    {
        byte[] data = new byte[32];
        RandomNumberGenerator.Fill(data);
    }

    public void TestStaticGetBytesCount()
    {
        byte[] data = RandomNumberGenerator.GetBytes(32);
    }

    public void TestStaticGetHexString()
    {
        string hex = RandomNumberGenerator.GetHexString(16);
    }

    public void TestStaticGetInt32()
    {
        int value = RandomNumberGenerator.GetInt32(100);
    }

    public void TestStaticGetInt32Range()
    {
        int value = RandomNumberGenerator.GetInt32(1, 100);
    }

    public void TestStaticGetItems()
    {
        int[] choices = new int[] { 1, 2, 3, 4, 5 };
        int[] items = RandomNumberGenerator.GetItems(choices, 3);
    }

    public void TestStaticGetString()
    {
        string alphabet = "abcdefghijklmnopqrstuvwxyz";
        string result = RandomNumberGenerator.GetString(alphabet, 10);
    }

    public void TestStaticShuffle()
    {
        int[] values = new int[] { 1, 2, 3, 4, 5 };
        RandomNumberGenerator.Shuffle(values);
    }

    // -------------------------------------------------------------------------
    // Section 3: RNGCryptoServiceProvider
    // -------------------------------------------------------------------------

    public void TestRngCspGetBytes()
    {
        RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
        byte[] data = new byte[32];
        rngCsp.GetBytes(data);
    }

    public void TestRngCspGetNonZeroBytes()
    {
        RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
        byte[] data = new byte[32];
        rngCsp.GetNonZeroBytes(data);
    }

    public void TestRngCspWithSeed()
    {
        byte[] seed = new byte[32];
        RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider(seed);
        byte[] data = new byte[32];
        rngCsp.GetBytes(data);
    }
}
