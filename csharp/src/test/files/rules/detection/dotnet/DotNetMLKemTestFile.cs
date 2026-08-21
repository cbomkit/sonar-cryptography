using System.Security.Cryptography;

public class DotNetMLKemTest
{
    public void TestMLKem512()
    {
        var key = MLKem.GenerateKey(MLKemAlgorithm.MLKem512); // Noncompliant
    }

    public void TestMLKem768()
    {
        var key = MLKem.GenerateKey(MLKemAlgorithm.MLKem768); // Noncompliant
    }

    public void TestMLKem1024()
    {
        var key = MLKem.GenerateKey(MLKemAlgorithm.MLKem1024); // Noncompliant
    }
}