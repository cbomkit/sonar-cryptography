import java.security.SecureRandom;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;

public class Issue297Sha256TestFile {

    private static final int staticEntropy1 = initStaticEntropy();
    private static final int staticEntropy2 = initStaticEntropy();
    private static final int staticEntropy3 = initStaticEntropy();
    private static final int staticEntropy4 = initStaticEntropy();

    void test() {
        SHA256Digest d = new SHA256Digest(); // Noncompliant {{(MessageDigest) SHA-256}}
        d.update((byte)staticEntropy1);
        d.update((byte)staticEntropy2);
        d.update((byte)staticEntropy3);
        d.update((byte)staticEntropy4);
        update(d, Object.class.hashCode());
        update(d, String.class.hashCode());
        byte[] b = new byte[d.getDigestSize()];
        d.doFinal(b, 0);
    }

    private static final int initStaticEntropy()
    {
        return new SecureRandom().nextInt() & 0xff;
    }
}