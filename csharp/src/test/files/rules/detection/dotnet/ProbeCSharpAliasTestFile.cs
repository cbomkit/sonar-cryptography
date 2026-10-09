using System.Security.Cryptography;

public class ProbeCSharpAlias
{
    public void TestViaAlias()
    {
        var aes = Aes.Create();
        var alias = aes;
        alias.Mode = CipherMode.CBC;
        alias.KeySize = 256;
    }
}
