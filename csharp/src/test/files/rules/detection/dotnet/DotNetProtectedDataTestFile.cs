/*
 * Comprehensive test file for the DPAPI (Windows Data Protection API) detection rules
 * (DotNetProtectedData.java).
 *
 * Covers:
 *   - ProtectedData.Protect(...) / Unprotect(...) / TryProtect(...) / TryUnprotect(...)
 *   - ProtectedMemory.Protect(...) / Unprotect(...)
 *   - DpapiDataProtector constructor + instance Protect(byte[]) / Unprotect(byte[])
 */

using System.Security.Cryptography;

public class DotNetProtectedDataTest
{
    // -------------------------------------------------------------------------
    // Section 1: ProtectedData
    // -------------------------------------------------------------------------

    public void TestProtectedDataProtect()
    {
        byte[] secret = new byte[16];
        byte[] entropy = new byte[8];
        byte[] encrypted = ProtectedData.Protect(secret, entropy, DataProtectionScope.CurrentUser);
    }

    public void TestProtectedDataUnprotect()
    {
        byte[] encrypted = new byte[32];
        byte[] entropy = new byte[8];
        byte[] secret = ProtectedData.Unprotect(encrypted, entropy, DataProtectionScope.CurrentUser);
    }

    public void TestProtectedDataTryProtect()
    {
        byte[] secret = new byte[16];
        byte[] entropy = new byte[8];
        byte[] destination = new byte[64];
        int bytesWritten;
        ProtectedData.TryProtect(secret, DataProtectionScope.LocalMachine, destination, out bytesWritten, entropy);
    }

    public void TestProtectedDataTryUnprotect()
    {
        byte[] encrypted = new byte[32];
        byte[] entropy = new byte[8];
        byte[] destination = new byte[32];
        int bytesWritten;
        ProtectedData.TryUnprotect(encrypted, DataProtectionScope.LocalMachine, destination, out bytesWritten, entropy);
    }

    // -------------------------------------------------------------------------
    // Section 2: ProtectedMemory
    // -------------------------------------------------------------------------

    public void TestProtectedMemoryProtect()
    {
        byte[] secret = new byte[16];
        ProtectedMemory.Protect(secret, MemoryProtectionScope.SameProcess);
    }

    public void TestProtectedMemoryUnprotect()
    {
        byte[] secret = new byte[16];
        ProtectedMemory.Unprotect(secret, MemoryProtectionScope.SameProcess);
    }

    // -------------------------------------------------------------------------
    // Section 3: DpapiDataProtector
    // -------------------------------------------------------------------------

    public void TestDpapiDataProtectorProtect()
    {
        DpapiDataProtector protector = new DpapiDataProtector("MyApp", "Giftcard", "1234");
        byte[] secret = new byte[16];
        byte[] encrypted = protector.Protect(secret);
    }

    public void TestDpapiDataProtectorUnprotect()
    {
        DpapiDataProtector protector = new DpapiDataProtector("MyApp", "Giftcard", "1234");
        byte[] encrypted = new byte[32];
        byte[] secret = protector.Unprotect(encrypted);
    }
}
