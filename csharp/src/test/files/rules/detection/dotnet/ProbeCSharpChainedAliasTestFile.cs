using System.Security.Cryptography;

public class ProbeCSharpChainedAliasTestFile
{
    public void TestViaChainedAlias()
    {
        var aes = Aes.Create();
        var alias1 = aes;
        var alias2 = alias1;
        alias2.Mode = CipherMode.CBC;
        alias2.KeySize = 256;
    }
}
