/*
 * OpenSSL's random byte source as C# reaches it. openssl-net declares
 * `RAND_bytes(byte[] buf, int num)` and calls it from its Random class.
 */

using System;
using System.Runtime.InteropServices;

public class OpenSslRandomUsage
{
    [DllImport("libcrypto")] private static extern int RAND_bytes(byte[] buf, int num);

    public void PublicBytes(byte[] buf)
    {
        RAND_bytes(buf, buf.Length);
    }

    public void PrivateBytes(byte[] buf)
    {
        Native.RAND_priv_bytes(buf, buf.Length);
    }

    public void Deprecated(byte[] buf)
    {
        Native.RAND_pseudo_bytes(buf, buf.Length);
    }

    public void WithLibraryContext(IntPtr libctx, byte[] buf)
    {
        Native.RAND_bytes_ex(libctx, buf, buf.Length, 256);
    }

    /*
     * Counter-check: configuring the DRBG type is not a use of it, and naming the concrete
     * construction from a RAND_bytes call site would be a guess about the deployment.
     */
    public void SetType(IntPtr libctx)
    {
        Native.RAND_set_DRBG_type(libctx, "CTR-DRBG", null, null, null);
    }

    /* Counter-check: RAND_seed and RAND_add feed the pool; they produce nothing. */
    public void Seed(byte[] buf)
    {
        Native.RAND_seed(buf, buf.Length);
    }
}
