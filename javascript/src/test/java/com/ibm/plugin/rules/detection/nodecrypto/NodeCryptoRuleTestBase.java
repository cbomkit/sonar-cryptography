/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2024 IBM
 */
package com.ibm.plugin.rules.detection.nodecrypto;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.TestBase;
import com.ibm.plugin.javascript.api.JavaScriptCheck;
import com.ibm.plugin.javascript.api.JavaScriptSymbol;
import com.ibm.plugin.javascript.api.Tree;
import com.ibm.plugin.javascript.language.JavaScriptScanContext;
import com.ibm.plugin.testing.JavaScriptVerifier;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

abstract class NodeCryptoRuleTestBase extends TestBase {

    private boolean sawTranslatedNodes;

    @Nonnull
    protected abstract String fixturePath();

    @Test
    void detectAndTranslate() throws Exception {
        sawTranslatedNodes = false;
        JavaScriptVerifier.verify(fixturePath(), this);
        assertThat(getUpdateCount()).isPositive();
        assertThat(sawTranslatedNodes).isTrue();
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<
                                    JavaScriptCheck, Tree, JavaScriptSymbol, JavaScriptScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        if (!nodes.isEmpty()) {
            sawTranslatedNodes = true;
        }
    }
}
