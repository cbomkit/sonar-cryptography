using System.Security.Cryptography;

public class DotNetMLKemTest
{
    public void TestMLKem512()
    {
        var key = MLKem512.GenerateKey(); // Noncompliant
    }

    public void TestMLKem768()
    {
        var key = MLKem768.GenerateKey(); // Noncompliant
    }

    public void TestMLKem1024()
    {
        var key = MLKem1024.GenerateKey(); // Noncompliant
    }
}