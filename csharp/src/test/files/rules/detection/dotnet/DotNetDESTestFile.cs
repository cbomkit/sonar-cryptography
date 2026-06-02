using System.Security.Cryptography;
public class DotNetDESTest {
    public void TestDesCreate() { var des = DES.Create(); } // Noncompliant
}
