using System.Security.Cryptography;

/*
 * Regression fixture for the false-positive fixes made when the C# detection engine's parameter
 * resolution was rewritten (see CSharpDetectionEngine's guards G1/G2/G4). Before that rewrite, each
 * scenario below silently produced a WRONG value instead of no value at all:
 *   - a property assigned from a method parameter resolved to the *parameter's own name* (G1),
 *     which a KeySizeFactory then further mangled into "name length in bytes x 8" bits (G2);
 *   - a variable reassigned to conflicting values resolved to whichever value happened to be
 *     checked first (G4).
 * Every scenario here must produce the primary AES detection and NOTHING else — see
 * DotNetFalsePositiveTest.java.
 */
public class DotNetFalsePositiveTest
{
    public void TestUnknownKeySizeParameter(int externalKeySize)
    {
        var aes = Aes.Create();
        aes.KeySize = externalKeySize;
    }

    public void TestUnknownModeParameter(CipherMode mode)
    {
        var aes = Aes.Create();
        aes.Mode = mode;
    }

    public void TestUnknownPaddingParameter(PaddingMode padding)
    {
        var aes = Aes.Create();
        aes.Padding = padding;
    }

    public void TestUnknownFeedbackSizeParameter(int feedbackSize)
    {
        var aes = Aes.Create();
        aes.FeedbackSize = feedbackSize;
    }

    public void TestReassignedKeySize()
    {
        var aes = Aes.Create();
        int ks = 128;
        ks = 256;
        aes.KeySize = ks;
    }
}
