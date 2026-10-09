using System.Security.Cryptography;

public class DotNetIncrementalHashTest
{
    public void IncrementalDigest(byte[] part1, byte[] part2)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(part1);
        hash.AppendData(part2);
        byte[] digest = hash.GetHashAndReset();
    }

    public void IncrementalMac(byte[] key, byte[] data)
    {
        using var mac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA384, key);
        mac.AppendData(data);
        byte[] tag = mac.GetHashAndReset();
    }

    public void LegacyRijndael()
    {
        using var rijndael = new RijndaelManaged();
        rijndael.KeySize = 256;
        rijndael.Mode = CipherMode.CBC;
    }
}
