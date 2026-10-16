#if __ANDROID__
using System.Security.Cryptography;

/*
 * A file that opens with a byte order mark and then a conditional directive -- the shape Visual
 * Studio produces by default, and the shape of lidgren-network-gen3's four platform files. The
 * mark must not stop the directive from being recognised: if the opening "#if" survives
 * preprocessing while its "#endif" is blanked, the grammar's own directive evaluation suppresses
 * the rest of the file and the SHA-1 below lexes to nothing at all.
 */
public class ByteOrderMark
{
    private static readonly SHA1 Sha = SHA1.Create();
}
#endif
