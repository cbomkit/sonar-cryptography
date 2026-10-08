using System.Security.Cryptography;

public class DotNetCngKeyTest
{
    public void CngRsaKey()
    {
        using var key = CngKey.Create(CngAlgorithm.Rsa);
    }

    public void CngEcdsaCurveKey()
    {
        using var key = CngKey.Create(CngAlgorithm.ECDsaP384, "my-key");
    }

    public void CngEcdhCurveKey()
    {
        using var key = CngKey.Create(CngAlgorithm.ECDiffieHellmanP256);
    }
}
