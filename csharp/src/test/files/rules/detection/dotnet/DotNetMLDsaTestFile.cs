using System.Security.Cryptography;

public class DotNetMLDsaTest
{
    public void TestMLDsa44()
    {
        var key = MLDsa44.GenerateKey(); // Noncompliant
    }

    public void TestMLDsa65()
    {
        var key = MLDsa65.GenerateKey(); // Noncompliant
    }

    public void TestMLDsa87()
    {
        var key = MLDsa87.GenerateKey(); // Noncompliant
    }
}