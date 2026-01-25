

public class JcaMessageDigestGetInstance2TestFile {

    void test() {
        java.security.Provider[] provider = java.security.Security.getProviders();
        java.security.MessageDigest md;
        if (provider.length > 1) {
            md = java.security.MessageDigest.getInstance("sha-384", provider[0]); // Noncompliant {{(MessageDigest) SHA-384}}
        } else {
            md = java.security.MessageDigest.getInstance("sha-384", "SUN"); // Noncompliant {{(MessageDigest) SHA-384}}
        }
    }
}