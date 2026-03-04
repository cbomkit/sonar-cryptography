using System.Security.Cryptography;

public class DotNetAESTest
{
    public void TestAesCreate()
    {
        var aes = Aes.Create(); // Noncompliant
    }

    public void TestAesManaged()
    {
        var aes = new AesManaged(); // Noncompliant
    }
}
