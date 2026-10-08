/*
 * Test fixture for the second round of CSharpDetectionEngine resolution work: object initializers,
 * chained calls, class fields, expression-bodied members, and the two inter-procedural cases
 * (a parameter resolved from its call sites, and a call resolved from its method's return value) —
 * plus the shapes that must deliberately stay unresolved. See ResolveAdvancedTest.java.
 */

public class ResolveAdvancedTestFile
{
    private static readonly int ReadonlyKeySize = 4096;
    private int _instanceKeySize = 2048;
    private int _mutatedKeySize = 1024;

    // --- positive: value must be resolved ---

    // Object initializer: `SetSize` is synthesized from `Size = 256` exactly like `k.SetSize(256)`.
    public void ObjectInitializer()
    {
        var k = new TestKeyGen { Size = 256 };
    }

    // Chained call: the inner TestKeyGen.Create() must be detected in its own right, and the
    // outer call's receiver must be the chain root, not the previous member name.
    public void ChainedCall()
    {
        TestKeyGen.Create().SetSize(512);
    }

    public void FromReadonlyField()
    {
        TestKeyGen.Create(ReadonlyKeySize);
    }

    public void FromInstanceField()
    {
        TestKeyGen.Create(_instanceKeySize);
    }

    // Expression-bodied method — the call must be found at all, and it is also the call site that
    // gives CreateWithSize's parameter its value below.
    public void ExpressionBodied() => CreateWithSize(3072);

    private void CreateWithSize(int size)
    {
        TestKeyGen.Create(size);
    }

    // Return value of a local helper, both arrow-bodied and block-bodied.
    private int ArrowSize() => 1536;

    private int BlockSize() { return 640; }

    public void FromArrowReturn()
    {
        TestKeyGen.Create(ArrowSize());
    }

    public void FromBlockReturn()
    {
        TestKeyGen.Create(BlockSize());
    }

    // --- negative: nothing may be resolved ---

    // A field the class overwrites elsewhere has no single value.
    public void FromMutatedField()
    {
        TestKeyGen.Create(_mutatedKeySize);
    }

    private void Mutate()
    {
        _mutatedKeySize = 8192;
    }

    // Array element access: must not report the array's length as the value.
    public void ArrayElement()
    {
        var sizes = new[] { 2048, 4096 };
        TestKeyGen.Create(sizes[0]);
    }

    // Ternary: the branches differ, so there is no single value — and above all the *condition*
    // must never be mistaken for one.
    public void Ternary(bool strong)
    {
        int flag = 1;
        TestKeyGen.Create(flag == 1 ? 4096 : 2048);
    }

    // Two callers disagree, so DisagreeingCallers' parameter stays unresolved.
    public void CallerA() => DisagreeingCallers(256);

    public void CallerB() => DisagreeingCallers(512);

    private void DisagreeingCallers(int size)
    {
        TestKeyGen.Create(size);
    }
}
