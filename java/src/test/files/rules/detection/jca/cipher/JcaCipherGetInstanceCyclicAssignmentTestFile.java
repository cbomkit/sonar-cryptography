import javax.crypto.Cipher;

public class JcaCipherGetInstanceCyclicAssignmentTestFile {

    private String algorithm = "AES/ECB/PKCS5Padding";
    private String copy = algorithm;

    public void swap() {
        // Cycle in the assignment graph: resolving `copy` follows its initializer to
        // `algorithm`, and resolving `algorithm` follows this assignment back to `copy`.
        algorithm = copy;
    }

    public void cipher() throws Exception {
        Cipher c = Cipher.getInstance(copy); // Noncompliant {{(BlockCipher) AES-128-ECB-PKCS5}}
    }
}
