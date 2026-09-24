/*
 * Test file for named-parameter matching in CSharpDetectionEngine.
 *
 * Exercised against two rules in CSharpNamedParameterDetectionTest.java:
 *   Single(marker)             — a single required named parameter.
 *   Combo(first, marker, note) — positional + required-named + optional-named together.
 */

public class CSharpNamedParameterDetectionTest
{
    // Named argument out of declared position — must resolve by keyword, not raw index.
    public void MarkerByKeywordReordered()
    {
        var other = 1;
        var value = 2;
        SomeType.Single(other, marker: value);
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

    // Required and optional named parameters both supplied, out of declared order.
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
}
