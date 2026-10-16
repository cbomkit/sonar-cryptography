using System;
using System.Collections.Generic;
using System.Security.Cryptography;

/*
 * Expressions that choose between values or hold several of them. None has a value this engine can
 * resolve, which used to mean the creations written inside them were not seen at all -- not their
 * parameters, the call site itself. The arms of a ternary or a switch expression, the elements of
 * a collection expression and the body of an expression-bodied lambda are all creations the code
 * performs, so they belong in an inventory even though no single one of them is "the" value.
 *
 * Found by diffing the findings against the source call sites over the scan corpus: every missed
 * site that was not a deliberate omission had one of these shapes, thirteen of them in ASP.NET
 * Core's data protection tests alone, where the factory-delegate idiom is the only spelling used.
 */
public class NoValueForms
{
    /* A lambda with an expression body, in the four spellings that occur. */
    public void FactoryDelegateNoParameter()  { Use(() => RSA.Create(1001)); }
    public void FactoryDelegateOneParameter() { Use(_ => RSA.Create(1002)); }
    public void FactoryDelegateNamedArgument() { UseNamed(factory: () => RSA.Create(1003)); }
    public void FactoryDelegateInLocal()      { Func<RSA> f = () => RSA.Create(1004); }
    public void FactoryDelegateCreation()     { Use(() => new RSACng(1005)); }

    /*
     * A switch expression arm. In fido2-net-lib the whole hash dispatch of CryptoUtils is written
     * this way, and in Microsoft IdentityModel so is the curve dispatch.
     */
    public RSA SwitchExpressionArms(int bits) => bits switch
    {
        256 => RSA.Create(1006),
        384 => new RSACng(1007),
        _ => null,
    };

    /* A switch expression whose arms are themselves factory delegates. */
    public Func<HMAC> SwitchArmsOfDelegates(string name) => name switch
    {
        "SHA256" => () => new HMACSHA256(),
        _ => () => new HMACSHA512(),
    };

    /* A C# 12 collection expression, with and without the spread operator. */
    public byte[] SpreadElement(byte[] head, byte[] tail) => [.. head, .. SHA256.HashData(tail)];

    public List<RSA> CreationElements() => [RSA.Create(1008), new RSACng(1009)];

    /* A ternary and a null-coalescing expression. */
    public RSA TernaryArms(bool strong) => strong ? RSA.Create(1010) : new RSACng(1011);

    public RSA CoalescingFallback(RSA given) => given ?? RSA.Create(1012);

    /*
     * Counter-checks. These must keep resolving to nothing: `is` and a comparison yield a boolean,
     * so neither may resolve to its operand, and a key size that arrives as a method parameter is
     * not knowable here -- the RSA must be reported without one rather than with a guess.
     */
    public bool IsPatternHasNoValue(object candidate) => candidate is RSACng;

    public bool ComparisonHasNoValue(int size) => size < 2048;

    public RSA UnresolvableKeySize(int bits) => RSA.Create(bits);

    /*
     * A target-typed `new()` (C# 9) names no type here, so no creation is reported for it -- but
     * its initializer is where the cryptography sits. Both spellings occur: an object initializer
     * as in fido2-net-lib, and a collection initializer of grouped entries as in ASP.NET Core's
     * TheoryData tables, where it is how every MAC in those tests is named.
     */
    public Holder TargetTypedObjectInitializer(int length) =>
        new() { Material = RandomNumberGenerator.GetBytes(length) };

    public List<Func<HMAC>> TargetTypedCollectionInitializer() =>
        new() { () => new HMACSHA256(), () => new HMACSHA512() };

    /*
     * A collection expression in statement position, with the creation buried in a lambda inside a
     * delegate constructor inside one of its elements. This is how fido2-net-lib writes its theory
     * data, and the statement path reaches a primary expression directly rather than through the
     * expression conversion, so it needs the same routing.
     */
    public static IEnumerable<object[]> StatementPositionCollection()
    {
        yield return ["a case", new Func<byte[], RSA>(_ => RSA.Create(1013)), "a refusal"];
    }

    public class Holder { public byte[] Material { get; set; } }

    private static void Use(Func<RSA> factory) { }
    private static void Use(Func<object, RSA> factory) { }
    private static void UseNamed(Func<RSA> factory) { }
}
