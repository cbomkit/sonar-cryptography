using System.Security.Cryptography;

/*
 * Property setters must only reach the object they are written on.
 *
 * A creation this engine cannot tie to a named variable leaves the receiver guard with nothing to
 * compare, and because operation rules match the receiver as MethodMatcher.ANY, every statement of
 * the enclosing block then becomes a candidate. The two Unrelated* methods are the cases that went
 * wrong: they reported AES-4096, a key size AES does not even have, read off a property of a
 * different class — once directly and once through an alias, which is the shape that matters
 * because alias resolution is exactly what makes a foreign receiver look like the tracked one.
 *
 * The remaining methods are the behaviour that has to survive: a setter on its own object, two
 * tracked objects keeping their own values, an untrackable creation next to a tracked one, and the
 * reassigned-alias cases that the G4 guard deliberately refuses to resolve.
 */
public class CSharpReceiverScopeTestFile
{
    public void UnrelatedReceiver()
    {
        Aes.Create();
        var transferConfig = new TransferConfig();
        transferConfig.KeySize = 4096;
    }

    public void UnrelatedReceiverThroughAlias()
    {
        Aes.Create();
        var transferConfig = new TransferConfig();
        var alias = transferConfig;
        alias.KeySize = 4096;
    }

    public void SameReceiver()
    {
        var aes = Aes.Create();
        aes.KeySize = 256;
    }

    public void TrackedAlias()
    {
        var aes = Aes.Create();
        var alias = aes;
        alias.KeySize = 192;
    }

    public void UnassignedCreationAlone()
    {
        Aes.Create();
    }

    public void TwoReceiversKeepTheirOwnValues()
    {
        var first = Aes.Create();
        first.KeySize = 128;
        var second = Aes.Create();
        second.KeySize = 192;
    }

    public void UnassignedCreationNextToATrackedOne()
    {
        Aes.Create();
        var tracked = Aes.Create();
        tracked.KeySize = 256;
    }

    public void ReassignedAlias()
    {
        var first = Aes.Create();
        var second = Aes.Create();
        var alias = first;
        alias = second;
        alias.KeySize = 256;
    }
}
