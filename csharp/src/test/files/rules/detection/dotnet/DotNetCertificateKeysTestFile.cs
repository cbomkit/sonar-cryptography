using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

/*
 * Certificate-backed asymmetric keys. Each method below mirrors a real call site from the projects
 * this plugin is exercised against — Bitwarden's license signing/verification
 * (src/Core/Billing/Models/Business/UserLicense.cs) and ASP.NET Core Data Protection's
 * EncryptedXmlDecryptor — none of which produced any algorithm finding before DotNetCertificateKeys.
 */
public class DotNetCertificateKeysTest
{
    public void RsaPublicKeyFromCertificate(X509Certificate2 certificate, byte[] data, byte[] signature)
    {
        using (var rsa = certificate.GetRSAPublicKey())
        {
            bool ok = rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
    }

    public void RsaPrivateKeyFromCertificate(X509Certificate2 certificate, byte[] data)
    {
        using (var rsa = certificate.GetRSAPrivateKey())
        {
            byte[] signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
    }

    public void EcdsaFromCertificate(X509Certificate2 certificate)
    {
        using var ecdsa = certificate.GetECDsaPrivateKey();
    }

    public void DsaFromCertificate(X509Certificate2 certificate)
    {
        using var dsa = certificate.GetDSAPublicKey();
    }

    public void EcdhFromCertificate(X509Certificate2 certificate)
    {
        using var ecdh = certificate.GetECDiffieHellmanPrivateKey();
    }

    /*
     * The other half of each accessor pair. The private and the public accessor used to share one
     * detection rule, so the one thing these method names state for free — which kind of key you
     * get — was thrown away. Both halves are exercised here so neither can regress to the other.
     */

    public void EcdsaPublicKeyFromCertificate(X509Certificate2 certificate)
    {
        using var ecdsa = certificate.GetECDsaPublicKey();
    }

    public void DsaPrivateKeyFromCertificate(X509Certificate2 certificate)
    {
        using var dsa = certificate.GetDSAPrivateKey();
    }

    public void EcdhPublicKeyFromCertificate(X509Certificate2 certificate)
    {
        using var ecdh = certificate.GetECDiffieHellmanPublicKey();
    }

    /*
     * Called as a plain static method on the declaring extension class instead of as an extension
     * method on the certificate. Both spellings compile to the same call and both appear in real
     * code — NuGet.Client and ASP.NET Core use the static form. It differs only in arity (the
     * certificate becomes the argument), which is what keeps the two rules from matching the same
     * call. Nullable target types are included because that is how most of these sites are written.
     */

    public void RsaPublicKeyStaticForm(X509Certificate2 certificate)
    {
        using var rsa = RSACertificateExtensions.GetRSAPublicKey(certificate);
    }

    public void EcdsaPrivateKeyStaticFormNullable(X509Certificate2 certificate)
    {
        ECDsa? ecdsa = ECDsaCertificateExtensions.GetECDsaPrivateKey(certificate);
    }
}
