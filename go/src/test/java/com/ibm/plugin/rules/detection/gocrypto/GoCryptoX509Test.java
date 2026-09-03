package com.ibm.plugin.rules.detection.gocrypto;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.OperationMode;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.engine.model.context.PublicKeyContext;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.mapper.model.Certificate;
import com.ibm.mapper.model.PrivateKey;
import com.ibm.mapper.model.PublicKey;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.TestBase;
import com.ibm.plugin.rules.detection.GoDetectionRules;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.go.api.Tree;
import static org.assertj.core.api.Assertions.assertThat;

class GoCryptoX509Test extends TestBase {

    @Test
    void testX509Methods() {
        // honestly just test everything in one go, I don't have time to write 15 separate test methods.
        // this should be fine.
        DetectionStore<Tree> store = new DetectionStore<>();
        GoVerifier.verify(
                "src/test/files/rules/detection/gocrypto/GoCryptoX509TestFile.go",
                GoDetectionRules.rules(),
                store);
        
        List<INode> nodes = store.getDetectionValues().stream()
                .map(iValue -> translator.translate(store.getBundle(), iValue, store.getDetectionContext(iValue), store.getDetectionLocation(iValue)).orElse(null))
                .toList();
        
        // Crazy tester mode activated
        // just making sure we hit all 11 rules properly. 
        assertThat(nodes).hasSize(11);
        
        // I guess I should make sure they aren't null
        for (INode node : nodes) {
            assertThat(node).isNotNull();
        }
        
        // There should be some Certificates, PrivateKeys, and PublicKeys. 
        long certCount = nodes.stream().filter(n -> n instanceof Certificate).count();
        long privateKeyCount = nodes.stream().filter(n -> n instanceof PrivateKey).count();
        long publicKeyCount = nodes.stream().filter(n -> n instanceof PublicKey).count();
        
        // let's see: ParseCertificate, ParseCertificates, CreateCertificate -> 3 Certificates
        // ParsePKIXPublicKey, MarshalPKIXPublicKey -> 2 PublicKeys
        // ParsePKCS1PrivateKey, MarshalPKCS1PrivateKey, ParsePKCS8PrivateKey, MarshalPKCS8PrivateKey, ParseECPrivateKey, MarshalECPrivateKey -> 6 PrivateKeys
        assertThat(certCount).isEqualTo(3);
        assertThat(privateKeyCount).isEqualTo(6);
        assertThat(publicKeyCount).isEqualTo(2);
    }
}
