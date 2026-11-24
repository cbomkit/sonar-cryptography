using System;
using System.Runtime.InteropServices;

/*
 * Schannel driven straight through SSPI, in the shapes hand-written P/Invoke takes. The
 * declarations below are copied in structure from dotnet/runtime's own
 * Interop.SSPI.cs / Interop.SchProtocols.cs / SslStreamPal.Windows.cs, which is where every
 * published C# Schannel binding comes from.
 */
internal static class SChannelConstants
{
    public const string UNISP_NAME = "Microsoft Unified Security Protocol Provider";
    public const string SCHANNEL_NAME = "Schannel";

    public const int SP_PROT_PCT1_CLIENT = 0x00000002;
    public const int SP_PROT_SSL2_CLIENT = 0x00000008;
    public const int SP_PROT_SSL3_SERVER = 0x00000010;
    public const int SP_PROT_SSL3_CLIENT = 0x00000020;
    public const int SP_PROT_TLS1_SERVER = 0x00000040;
    public const int SP_PROT_TLS1_CLIENT = 0x00000080;
    public const int SP_PROT_TLS1_0_CLIENT = 0x00000080;
    public const int SP_PROT_TLS1_1_CLIENT = 0x00000200;
    public const int SP_PROT_TLS1_2_SERVER = 0x00000400;
    public const int SP_PROT_TLS1_2_CLIENT = 0x00000800;
    public const int SP_PROT_TLS1_2 = SP_PROT_TLS1_2_SERVER | SP_PROT_TLS1_2_CLIENT;
    public const int SP_PROT_TLS1_3_SERVER = 0x00001000;
    public const int SP_PROT_TLS1_3_CLIENT = 0x00002000;
    public const int SP_PROT_DTLS_CLIENT = 0x00020000;
    public const int SP_PROT_DTLS1_0_CLIENT = 0x00020000;
    public const int SP_PROT_DTLS1_2_CLIENT = 0x00080000;
    public const int SP_PROT_NONE = 0;
    public const int SP_PROT_ALL = 0x7fffffff;
}

internal struct SCHANNEL_CRED
{
    public int dwVersion;
    public int cCreds;
    public IntPtr paCred;
    public IntPtr hRootStore;
    public int cMappers;
    public IntPtr aphMappers;
    public int cSupportedAlgs;
    public IntPtr palgSupportedAlgs;
    public int grbitEnabledProtocols;
    public int dwMinimumCipherStrength;
    public int dwMaximumCipherStrength;
    public int dwSessionLifespan;
    public int dwFlags;
    public int dwCredFormat;
}

internal struct SCH_CREDENTIALS
{
    public int dwVersion;
    public int dwCredFormat;
    public int cCreds;
    public IntPtr paCred;
    public IntPtr hRootStore;
    public int dwSessionLifespan;
    public int dwFlags;
    public int cTlsParameters;
    public IntPtr pTlsParameters;
}

internal struct TLS_PARAMETERS
{
    public int cAlpnIds;
    public IntPtr rgstrAlpnIds;
    public uint grbitDisabledProtocols;
    public int cDisabledCrypto;
    public IntPtr pDisabledCrypto;
    public int dwFlags;
}

internal struct CRYPTO_SETTINGS
{
    public int eAlgorithmUsage;
    public IntPtr strCngAlgId;
    public int cChainingModes;
    public IntPtr rgstrChainingModes;
    public int dwMinBitLength;
    public int dwMaxBitLength;
}

internal static class SspiCli
{
    [DllImport("secur32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern int AcquireCredentialsHandle(
        string pszPrincipal,
        string pszPackage,
        int fCredentialUse,
        IntPtr pvLogonId,
        IntPtr pAuthData,
        IntPtr pGetKeyFn,
        IntPtr pvGetKeyArgument,
        out long phCredential,
        out long ptsExpiry);
}

public class SchannelUsage
{
    private const int SECPKG_CRED_OUTBOUND = 0x2;
    private const int SECPKG_CRED_INBOUND = 0x1;

    /*
     * A constant of this same class, referenced without a qualifier further down. Declared here
     * so the counter-check below is the real shape and not an approximation of it.
     */
    private const int SP_PROT_TLS1_2_CLIENT = 0x00000800;

    /* The package name written as a member access: the dominant idiom, and the one that names it. */
    public void OutboundCredential(IntPtr authData)
    {
        long credential;
        long expiry;
        SspiCli.AcquireCredentialsHandle(
            null,
            SChannelConstants.UNISP_NAME,
            SECPKG_CRED_OUTBOUND,
            IntPtr.Zero,
            authData,
            IntPtr.Zero,
            IntPtr.Zero,
            out credential,
            out expiry);
    }

    /* The other Schannel package name, written as a literal. */
    public void InboundCredential(IntPtr authData)
    {
        long credential;
        long expiry;
        SspiCli.AcquireCredentialsHandle(
            null,
            "Schannel",
            SECPKG_CRED_INBOUND,
            IntPtr.Zero,
            authData,
            IntPtr.Zero,
            IntPtr.Zero,
            out credential,
            out expiry);
    }

    /* A local string constant: it resolves through to the documented package string. */
    public void ViaLocalConstant(IntPtr authData)
    {
        const string package = "Microsoft Unified Security Protocol Provider";
        long credential;
        long expiry;
        SspiCli.AcquireCredentialsHandle(
            null,
            package,
            SECPKG_CRED_OUTBOUND,
            IntPtr.Zero,
            authData,
            IntPtr.Zero,
            IntPtr.Zero,
            out credential,
            out expiry);
    }

    /* The same call with inline out-variable declarations, which C# 7 allows and real code uses. */
    public void InlineOutVariables(IntPtr authData)
    {
        SspiCli.AcquireCredentialsHandle(
            null,
            SChannelConstants.SCHANNEL_NAME,
            SECPKG_CRED_OUTBOUND,
            IntPtr.Zero,
            authData,
            IntPtr.Zero,
            IntPtr.Zero,
            out long credential,
            out long expiry);
    }

    /* The legacy credential, built with an object initializer. */
    public void LegacyCredential()
    {
        var cred = new SCHANNEL_CRED
        {
            dwVersion = 4,
            grbitEnabledProtocols = SChannelConstants.SP_PROT_TLS1_2_CLIENT,
            dwMinimumCipherStrength = 128,
            dwMaximumCipherStrength = 256,
        };
    }

    /* A flags combination: a set of versions, not a number. */
    public void TwoVersions()
    {
        var cred = new SCHANNEL_CRED();
        cred.grbitEnabledProtocols =
            SChannelConstants.SP_PROT_TLS1_2_CLIENT | SChannelConstants.SP_PROT_TLS1_3_CLIENT;
    }

    /* Client and server flags of the same version, plus the server|client alias. */
    public void BothDirections()
    {
        var cred = new SCHANNEL_CRED();
        cred.grbitEnabledProtocols = SChannelConstants.SP_PROT_TLS1_2_SERVER;
        cred.grbitEnabledProtocols = SChannelConstants.SP_PROT_TLS1_3_SERVER;
        cred.grbitEnabledProtocols = SChannelConstants.SP_PROT_TLS1_2;
    }

    /* TLS 1.1 and both spellings of the TLS 1.0 flag. */
    public void OlderTlsVersions()
    {
        var cred = new SCHANNEL_CRED();
        cred.grbitEnabledProtocols = SChannelConstants.SP_PROT_TLS1_1_CLIENT;
        cred.grbitEnabledProtocols = SChannelConstants.SP_PROT_TLS1_CLIENT;
        cred.grbitEnabledProtocols = SChannelConstants.SP_PROT_TLS1_0_CLIENT;
        cred.grbitEnabledProtocols = SChannelConstants.SP_PROT_TLS1_SERVER;
    }

    /* SSL is not TLS: it keeps its own name so a reader sees what was offered. */
    public void LegacySsl()
    {
        var cred = new SCHANNEL_CRED();
        cred.grbitEnabledProtocols = SChannelConstants.SP_PROT_SSL3_CLIENT;
        cred.grbitEnabledProtocols = SChannelConstants.SP_PROT_SSL3_SERVER;
        cred.grbitEnabledProtocols = SChannelConstants.SP_PROT_SSL2_CLIENT;
    }

    /* DTLS, versioned and unversioned. */
    public void Datagram()
    {
        var cred = new SCHANNEL_CRED();
        cred.grbitEnabledProtocols = SChannelConstants.SP_PROT_DTLS1_2_CLIENT;
        cred.grbitEnabledProtocols = SChannelConstants.SP_PROT_DTLS1_0_CLIENT;
        cred.grbitEnabledProtocols = SChannelConstants.SP_PROT_DTLS_CLIENT;
    }

    /* Zero is the documented recommendation: Schannel picks, so no version is known. */
    public void PlatformDefault()
    {
        var cred = new SCHANNEL_CRED();
        cred.grbitEnabledProtocols = SChannelConstants.SP_PROT_NONE;
    }

    /* The modern credential. It has no enabled-protocol field at all. */
    public void ModernCredential()
    {
        var cred = new SCH_CREDENTIALS
        {
            dwVersion = 5,
            cTlsParameters = 1,
        };
    }

    /*
     * Counter-check: grbitDisabledProtocols is the same flag vocabulary with the opposite
     * meaning. A disabled protocol is not a protocol in use, so nothing is reported -- not even
     * the bare TLS that the structure's existence would support.
     */
    public void DisabledProtocols()
    {
        var parameters = new TLS_PARAMETERS
        {
            grbitDisabledProtocols = 0x00000020,
        };
        parameters.grbitDisabledProtocols = 0x00000800;
    }

    /*
     * Counter-check: CRYPTO_SETTINGS is reachable only through TLS_PARAMETERS.pDisabledCrypto and
     * is documented as "disabled cryptographic settings". Its algorithm usage, its chaining modes
     * and its bit lengths all describe cryptography being switched off, so none of them becomes a
     * component.
     */
    public void DisabledCrypto()
    {
        var settings = new CRYPTO_SETTINGS
        {
            eAlgorithmUsage = 2,
            cChainingModes = 1,
            dwMinBitLength = 0,
            dwMaxBitLength = 128,
        };
        settings.dwMinBitLength = 256;
        settings.dwMaxBitLength = 256;
    }

    /*
     * Counter-check: a bare reference to a const declared in the same file resolves through to
     * its number, and a number is not a protocol name. The known recall gap, asserted so that it
     * stays a gap rather than silently becoming a guess.
     */
    public void UnqualifiedConstant()
    {
        var cred = new SCHANNEL_CRED();
        cred.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;
    }

    /* Counter-check: a numeric literal, however correct the bit is. */
    public void NumericFlag()
    {
        var cred = new SCHANNEL_CRED();
        cred.grbitEnabledProtocols = 0x00000800;
    }

    /* Counter-check: the flags arrive as a method parameter, so none may be invented. */
    public void FromParameter(int protocols)
    {
        var cred = new SCHANNEL_CRED();
        cred.grbitEnabledProtocols = protocols;
    }

    /* Counter-check: a flag Schannel has not honoured since Windows 2000, and a whole-range mask. */
    public void UnreportableFlags()
    {
        var cred = new SCHANNEL_CRED();
        cred.grbitEnabledProtocols = SChannelConstants.SP_PROT_PCT1_CLIENT;
        cred.grbitEnabledProtocols = SChannelConstants.SP_PROT_ALL;
    }

    /* Counter-check: a name that is not a flag of this field at all. */
    public void UnknownName(Options options)
    {
        var cred = new SCHANNEL_CRED();
        cred.grbitEnabledProtocols = options.Preferred;
    }

    /*
     * Counter-check: the cipher-strength floor and ceiling are real policy, but they name no
     * algorithm, and a bit length with nothing to attach it to is not a component.
     */
    public void CipherStrengthOnly()
    {
        var cred = new SCHANNEL_CRED();
        cred.dwMinimumCipherStrength = 128;
        cred.dwMaximumCipherStrength = 256;
    }

    /*
     * Counter-check: a field of an unrelated type whose name merely resembles the Win32 one. The
     * exact Hungarian-notation name is the guard, and nothing weaker matches.
     */
    public void SimilarlyNamedField(Options options)
    {
        options.EnabledProtocols = SChannelConstants.SP_PROT_TLS1_2_CLIENT;
        options.GrbitEnabledProtocols = SChannelConstants.SP_PROT_TLS1_3_CLIENT;
    }

    /*
     * Counter-check: something else called AcquireCredentialsHandle. The receiver is matched as
     * ANY, so only the nine-argument arity of the SSPI function keeps this quiet.
     */
    public void UnrelatedHelper(Vault vault)
    {
        vault.AcquireCredentialsHandle("user", "Schannel", 1);
    }

    /* Counter-check: a security package that is not Schannel. */
    public void NegotiatePackage(IntPtr authData)
    {
        long credential;
        long expiry;
        SspiCli.AcquireCredentialsHandle(
            null,
            "Negotiate",
            SECPKG_CRED_OUTBOUND,
            IntPtr.Zero,
            authData,
            IntPtr.Zero,
            IntPtr.Zero,
            out credential,
            out expiry);
    }

    /* Counter-check: the package name arrives as a parameter, so none may be invented. */
    public void PackageFromParameter(string package, IntPtr authData)
    {
        long credential;
        long expiry;
        SspiCli.AcquireCredentialsHandle(
            null,
            package,
            SECPKG_CRED_OUTBOUND,
            IntPtr.Zero,
            authData,
            IntPtr.Zero,
            IntPtr.Zero,
            out credential,
            out expiry);
    }
}

public class Options
{
    public int Preferred;
    public int EnabledProtocols;
    public int GrbitEnabledProtocols;
}

public class Vault
{
    public void AcquireCredentialsHandle(string user, string package, int use)
    {
    }
}
