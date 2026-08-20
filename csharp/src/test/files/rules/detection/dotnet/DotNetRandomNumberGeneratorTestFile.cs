/*
 * Comprehensive test file for RandomNumberGenerator / RNGCryptoServiceProvider detection rules
 * (DotNetRandomNumberGenerator.java).
 *
 * Covers:
 *   - RandomNumberGenerator.Create() / Create(string) + instance GetBytes/GetNonZeroBytes
 *   - RandomNumberGenerator's static-only methods: Fill, GetBytes(int)/(Span<byte>),
 *     GetHexString, GetInt32, GetItems, GetNonZeroBytes(Span<byte>), GetString, Shuffle
 *   - RNGCryptoServiceProvider constructor overloads + instance GetBytes/GetNonZeroBytes
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

    public void TestStaticGetNonZeroBytes()
    {
        byte[] data = new byte[32];
        RandomNumberGenerator.GetNonZeroBytes(data);
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
