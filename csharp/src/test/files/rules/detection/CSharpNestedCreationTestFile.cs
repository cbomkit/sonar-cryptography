/*
 * Creation sites that are not statements of their own. All of these were previously invisible: not
 * just their parameters but the whole finding, because the converter only treated a creation in
 * statement position as a call site.
 *
 * The shapes are taken from Microsoft.IdentityModel, where test data and key registries are built
 * exactly this way.
 */

using System.Collections.Generic;
using System.Security.Cryptography;

public class CSharpNestedCreation
{
    // Field initializer, outside every method body.
    private readonly RSA _fromFieldInitializer = RSA.Create(3072);

    // Auto-property initializer, which the grammar models separately from a field.
    private RSA FromPropertyInitializer { get; } = RSA.Create(1024);

    // Creation passed straight into another constructor, the wrapper-type pattern.
    public object NestedInConstructor() => new Wrapper(RSA.Create(2048));

    // Creation passed into a method, the registration pattern.
    public void NestedInMethodArgument() => Use(RSA.Create(4096));

    // Creation as an object-initializer member value, the shape of
    // `SecurityKey = new RsaSecurityKey(RSA.Create(2048))` in test data builders.
    public object InObjectInitializer() => new Holder { Key = new Wrapper(RSA.Create(7680)) };

    // The same with the creation directly as the member value.
    public object InObjectInitializerDirect() => new Holder { Key = ECDsa.Create(ECCurve.NamedCurves.nistP384) };

    // Creation inside a collection-initializer element.
    public List<Holder> InCollectionInitializer() =>
        new List<Holder> { new Holder { Key = ECDsa.Create(ECCurve.NamedCurves.nistP521) } };

    // Assignment to a field from inside a method body.
    private RSA _assigned;
    public void AssignToField() { _assigned = new Wrapper2(RSA.Create(15360)).Key; }

    private void Use(RSA rsa) { }
}

public class Wrapper { public Wrapper(RSA r) { } }
public class Wrapper2 { public Wrapper2(RSA r) { Key = r; } public RSA Key { get; } }
public class Holder { public object Key { get; set; } }
