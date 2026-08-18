using System.Security.Cryptography;

public class DotNetAESPropertyTest
{
    public void TestAesWithProperties()
    {
        var aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.KeySize = 256;
        aes.Padding = PaddingMode.PKCS7;
    }

    public void TestAesManagedWithMode()
    {
        var aes = new AesManaged();
        aes.Mode = CipherMode.ECB;
        aes.KeySize = 128;
    }
}
