/*
 * Test file for named-parameter matching in CSharpDetectionEngine.
 *
 * Exercised against three rules in CSharpNamedParameterDetectionTest.java:
 *   Single(marker)                    — a single required named parameter.
 *   Combo(first, marker, note)        — positional + required-named + optional-named together.
 *   Typed(iterations, hashAlgorithm)  — two required named parameters with distinctive declared
 *                                       types, exercising the binder's type-directed step.
 */

public class CSharpNamedParameterDetectionTest
{
    // Marker passed by keyword. Must resolve by keyword, not by raw index.
    public void MarkerByKeyword()
    {
        var value = 2;
        SomeType.Single(marker: value);
    }

    // No named arguments at all — must still resolve via positional fallback (index 0).
    public void MarkerByPositionalFallback()
    {
        var value = 2;
        SomeType.Single(value);
    }

    // Enough arguments, but none named "marker" — the fallback slot (index 0) is occupied by a
    // DIFFERENT named argument. Must not be misattributed to "marker"; call must be rejected.
    public void WrongKeywordNotMisattributed()
    {
        var x = 1;
        SomeType.Single(other: x);
    }

    // Required "marker" named parameter entirely absent — call must be rejected, no finding.
    public void MissingMarker()
    {
        SomeType.Single();
    }

    // More arguments than the rule declares parameters. A one-parameter overload cannot accept two
    // arguments, so this is a different overload than the rule describes and must be rejected
    // rather than silently binding index 0.
    public void TooManyArgumentsForDeclaredArity()
    {
        var a = 1;
        var b = 2;
        SomeType.Single(a, b);
    }

    // -------------------------------------------------------------------------
    // Combo(first, marker, note) — first: positional, marker: required named,
    // note: optional named
    // -------------------------------------------------------------------------

    // Pure positional call on a rule declared with named parameters — old-style calls must
    // still resolve entirely via positional fallback, including the optional "note".
    public void ComboAllPositional()
    {
        var a = 1;
        var b = 2;
        var c = 3;
        SomeType.Combo(a, b, c);
    }

    // Required and optional named parameters both supplied, out of declared order. This is the
    // reordering case: "note" precedes "marker" in the call but must not be bound to it.
    public void ComboOptionalPresent()
    {
        var a = 1;
        var b = 2;
        var c = 3;
        SomeType.Combo(a, note: c, marker: b);
    }

    // Optional "note" omitted entirely — rule must still match; "note" is simply not processed.
    public void ComboOptionalAbsent()
    {
        var a = 1;
        var b = 2;
        SomeType.Combo(a, marker: b);
    }

    // -------------------------------------------------------------------------
    // Typed(iterations: int, hashAlgorithm: HashAlgorithmName)
    // -------------------------------------------------------------------------

    // Declared order. Both parameters bind positionally and both values are captured.
    public void TypedInDeclaredOrder()
    {
        SomeType.Typed(100000, HashAlgorithmName.SHA256);
    }

    // Same arity, parameters in the opposite order — the shape of the two five-parameter layouts
    // of Rfc2898DeriveBytes.Pbkdf2. Positional binding is refused on both slots because each
    // argument's type is definitely incompatible with the parameter at its index; the type-directed
    // step then binds each parameter to the one argument that can supply it.
    public void TypedInOppositeOrder()
    {
        SomeType.Typed(HashAlgorithmName.SHA384, 200000);
    }

    // Two ints, so nothing in the call can supply the HashAlgorithmName parameter. A call that
    // cannot fill a required parameter is a different overload than the rule describes, so it is
    // rejected entirely rather than detected with a guessed or missing hash. This is why a rule set
    // has to enumerate every overload arity of a method it covers.
    public void TypedWrongOverloadRejected()
    {
        SomeType.Typed(300000, 8);
    }
}
