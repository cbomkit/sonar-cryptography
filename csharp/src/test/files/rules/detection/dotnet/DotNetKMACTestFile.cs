/*
 * Test file for the System.Security.Cryptography KMAC detection rules.
 *
 * Kmac128/Kmac256 and their XOF variants take the MAC key as the first constructor argument and an
 * optional customization string as the second. The key length is recorded where the call states it.
 */

using System.Security.Cryptography;

public class DotNetKMACTest {
    public void TestKmac128()    { byte[] key = new byte[16]; var m = new Kmac128(key); }    // Noncompliant
    public void TestKmac256()    { byte[] key = new byte[32]; var m = new Kmac256(key); }    // Noncompliant
    public void TestKmacXof128() { byte[] key = new byte[16]; var m = new KmacXof128(key); } // Noncompliant
    public void TestKmacXof256() { byte[] key = new byte[32]; var m = new KmacXof256(key); } // Noncompliant

    // With the optional customization string, which carries no length worth recording.
    public void TestKmac256WithCustomization()
    {
        var m = new Kmac256(new byte[48], new byte[8]);
    }

    // The key written as a keyword argument.
    public void TestKmac128NamedKey()
    {
        var m = new Kmac128(key: new byte[20]);
    }

    // A key the engine cannot measure: only the algorithm may be reported.
    public void TestKmac128UnknownKey()
    {
        byte[] key = System.Convert.FromBase64String(
            System.Environment.GetEnvironmentVariable("KMAC_KEY"));
        var m = new Kmac128(key);
    }
}
