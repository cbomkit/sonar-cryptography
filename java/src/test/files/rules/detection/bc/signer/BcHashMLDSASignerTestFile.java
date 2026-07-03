import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.HashMLDSASigner;

class BcHashMLDSASignerTestFile {

    void test(){
        HashMLDSASigner signer = new HashMLDSASigner(); // Noncompliant {{(Signature) SHA-512-ML-DSA-44}}
        signer.init(true, new MLDSAKeyParameters(true, MLDSAParameters.ml_dsa_44_with_sha512));
    }
}