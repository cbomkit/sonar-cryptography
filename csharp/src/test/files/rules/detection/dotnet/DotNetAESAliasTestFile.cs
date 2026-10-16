using System.Security.Cryptography;

public class DotNetAESAliasTestFile
{
    public void TestViaAlias()
    {
        var aes = Aes.Create();
        var alias = aes;
        alias.Mode = CipherMode.CBC;
        alias.KeySize = 256;
    }
}
