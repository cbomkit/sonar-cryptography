using System.Security.Cryptography;
public class DotNetTripleDESTest {
    public void TestTripleDesCreate() { var des = TripleDES.Create(); } // Noncompliant
}
