/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2024 IBM
 */
package com.ibm.plugin.rules.detection.nodecrypto;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.plugin.TestBase;
import com.ibm.plugin.javascript.api.JavaScriptCheck;
import com.ibm.plugin.javascript.api.JavaScriptSymbol;
import com.ibm.plugin.javascript.api.Tree;
import com.ibm.plugin.javascript.language.JavaScriptScanContext;
import com.ibm.plugin.testing.JavaScriptVerifier;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

class NodeCryptoVariableResolutionTest extends TestBase {

    @Test
    void resolvesVariableAlgorithm() throws Exception {
        JavaScriptVerifier.verify(
                "rules/detection/nodecrypto/NodeCryptoVariableResolutionTestFile.js", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<
                                    JavaScriptCheck, Tree, JavaScriptSymbol, JavaScriptScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        if (findingId == 0) {
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(DigestContext.class);
            IValue<Tree> value = detectionStore.getDetectionValues().get(0);
            assertThat(value).isInstanceOf(Algorithm.class);
            assertThat(value.asString()).isEqualToIgnoringCase("sha256");
            assertThat(nodes).isNotEmpty();
            assertThat(nodes.get(0).getKind()).isEqualTo(MessageDigest.class);
        }
    }
}
