using System.Security.Cryptography;
public class DotNetKMACTest {
    public void TestKmac128()    { byte[] key = new byte[16]; var m = new Kmac128(key); }    // Noncompliant
    public void TestKmac256()    { byte[] key = new byte[32]; var m = new Kmac256(key); }    // Noncompliant
    public void TestKmacXof128() { byte[] key = new byte[16]; var m = new KmacXof128(key); } // Noncompliant
    public void TestKmacXof256() { byte[] key = new byte[32]; var m = new KmacXof256(key); } // Noncompliant
}
