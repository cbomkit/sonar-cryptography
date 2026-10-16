using System;
using System.Security.Cryptography;

/*
 * One call site must produce one finding. The shapes below are the ones where the converter runs
 * over the same expression more than once, so a call site inside them was at risk of being
 * counted twice.
 */
public class ExpressionBodiedMembers
{
    /*
     * A block lambda as the body of an expression-bodied method. The arrow body used to be
     * converted twice -- once to register what the method returns, once to collect the body's
     * statements -- and because converting a lambda turns its block into a body of its own, this
     * single RSA.Create(2048) was reported twice.
     */
    public Func<RSA> Factory() => () => { return RSA.Create(2048); };

    /* The same shape on a property, which takes the generic expression-bodied path. */
    public Func<RSA> FactoryProperty => () => { return RSA.Create(3072); };

    /* An ordinary expression-bodied method, to pin that the single report still happens at all. */
    public RSA Direct() => RSA.Create(4096);
}
