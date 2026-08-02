import javax.net.ssl.*;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class SSLContextGetInstanceTestFile {

    void test() throws KeyManagementException, NoSuchAlgorithmException {
        // Noncompliant@+1 {{(TLS) TLSv1.2}}
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(null, null, new SecureRandom());
        SSLSocketFactory socketFactory = sslContext.getSocketFactory();
    }

    void testSslv3() throws KeyManagementException, NoSuchAlgorithmException {
        // Noncompliant@+1 {{(TLS) SSLv3}}
        SSLContext sslContext = SSLContext.getInstance("SSLv3");
        sslContext.init(null, null, new SecureRandom());
    }

    void testDtlsv12() throws KeyManagementException, NoSuchAlgorithmException {
        // Noncompliant@+1 {{(TLS) DTLSv1.2}}
        SSLContext sslContext = SSLContext.getInstance("DTLSv1.2");
        sslContext.init(null, null, new SecureRandom());
    }

}