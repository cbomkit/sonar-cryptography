using System.Security.Cryptography;
public class DotNetRC2Test {
    public void TestRc2Create() { var rc2 = RC2.Create(); } // Noncompliant
}
