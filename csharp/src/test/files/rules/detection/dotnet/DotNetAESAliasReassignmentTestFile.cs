using System.Security.Cryptography;

public class DotNetAESAliasReassignmentTestFile
{
    public void TestAliasReassignment()
    {
        var first = Aes.Create();
        var second = first;
        var alias = second;
        alias.Mode = CipherMode.CBC;
        alias.KeySize = 256;
    }
}
