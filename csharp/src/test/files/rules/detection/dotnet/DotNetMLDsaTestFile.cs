using System.Security.Cryptography;

public class DotNetMLDsaTest
{
    public void TestMLDsa44()
    {
        var key = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa44); // Noncompliant
    }

    public void TestMLDsa65()
    {
        var key = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65); // Noncompliant
    }

    public void TestMLDsa87()
    {
        var key = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa87); // Noncompliant
    }
}