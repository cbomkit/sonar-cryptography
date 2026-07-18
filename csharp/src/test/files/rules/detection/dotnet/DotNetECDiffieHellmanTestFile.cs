using System.Security.Cryptography;
public class DotNetECDiffieHellmanTest {
    public void TestECDHCreate() { var ecdh = ECDiffieHellman.Create(); } // Noncompliant
}
