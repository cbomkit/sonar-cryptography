using System.Security.Cryptography;
public class DotNetDSATest {
    public void TestDsaCreate() { var dsa = DSA.Create(); } // Noncompliant
}
