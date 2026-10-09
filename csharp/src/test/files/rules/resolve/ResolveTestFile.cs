/*
 * Test fixture for engine-level parameter/value resolution (CSharpDetectionEngine), independent of
 * any real System.Security.Cryptography API — uses fictitious TestKeyGen/TestEcGen types so each
 * scenario isolates exactly one resolution path without interference from unrelated production
 * rules. See ResolveTest.java for the corresponding assertions.
 */

public class ResolveTestFile
{
    private const int FixedKeySize = 4096;

    // -------------------------------------------------------------------------
    // Positive cases: syntactically certain values must be resolved
    // -------------------------------------------------------------------------

    public void TestLocalLiteral()
    {
        int ks = 2048;
        TestKeyGen.Create(ks);
    }

    public void TestConstField()
    {
        TestKeyGen.Create(FixedKeySize);
    }

    public void TestArraySize()
    {
        TestKeyGen.CreateFromBytes(new byte[32]);
    }

    public void TestBinaryExpression()
    {
        TestKeyGen.Create(2040 + 8);
    }

    public void TestNestedMemberAccess()
    {
        TestEcGen.Create(TestCurve.Named.nistP256);
    }

    public void TestBlockFlattening()
    {
        var k = TestKeyGen.Create();
        if (true)
        {
            k.SetSize(3072);
        }
    }

    // -------------------------------------------------------------------------
    // Negative cases: no syntactically certain value exists — nothing must be emitted
    // -------------------------------------------------------------------------

    public void TestMethodParameter(int ks)
    {
        TestKeyGen.Create(ks);
    }

    public void TestReassignedVariable()
    {
        int ks = 2048;
        ks = 4096;
        TestKeyGen.Create(ks);
    }

    public void TestStringNeverBecomesKeySize()
    {
        const string algName = "RSA";
        TestKeyGen.Create(algName);
    }
}
