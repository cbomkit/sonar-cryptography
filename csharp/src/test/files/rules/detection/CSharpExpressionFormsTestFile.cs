using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

/*
 * Expression forms that used to hide a call site completely, not just its parameters.
 *
 * Each of the four was found by scanning real code and then looking for why a call site the source
 * clearly contains produced no finding at all. The counter-checks at the bottom matter just as
 * much: `is` and a comparison yield a boolean, so they must not resolve to their operand, and a
 * compound operator is not modelled.
 */

public class Base
{
    public Base(SymmetricAlgorithm alg) { }
    public Base(int order, SymmetricAlgorithm alg) { }
}

/*
 * A creation inside a constructor initializer. Taken from lidgren-network-gen3, where the only
 * cryptography of NetAESEncryption, NetTripleDESEncryption, NetDESEncryption and NetRC2Encryption
 * is written exactly like this and was invisible.
 */
public class ConstructorInitializers : Base
{
    public ConstructorInitializers() : base(new AesCryptoServiceProvider()) { }

    // The same with no block body of its own.
    public ConstructorInitializers(bool withOrder) : base(1, new TripleDESCryptoServiceProvider());
}

public class OtherForms
{
    private static RSA _lazy;
    private static RSA _lazyProperty;

    /*
     * An `as` conversion on the result. Four call sites in Microsoft IdentityModel and NuGet.Client
     * are written this way, all of them certificate keys.
     */
    public void AsConversionOnCertificateKey(X509Certificate2 certificate)
    {
        var rsa = certificate.GetRSAPrivateKey() as RSACng;
    }

    public void AsConversionOnCreate()
    {
        var rsa = RSA.Create(3072) as RSACng;
    }

    /* A coalescing assignment, the lazy-initialisation idiom. */
    public RSA CoalescingAssignmentInBlock()
    {
        _lazy ??= RSA.Create(4096);
        return _lazy;
    }

    /* The same idiom written as an expression-bodied property, as in MlDsaKeyingMaterial. */
    public static RSA CoalescingAssignmentAsProperty => _lazyProperty ??= RSA.Create(7680);

    /* Counter-check: `is` yields a boolean, so it must not resolve to the operand. */
    public bool IsPatternIsNotAConversion(object candidate)
    {
        return candidate is RSACng;
    }

    /* Counter-check: a comparison has no single value either. */
    public bool ComparisonHasNoValue(int size)
    {
        return size < 2048;
    }
}
