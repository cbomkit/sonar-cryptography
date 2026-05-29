/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2024 PQCA
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to you under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.ibm.plugin.rules.issues;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.MacSize;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.MacContext;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.TestBase;
import com.ibm.plugin.rules.detection.bc.BouncyCastleJars;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

class ParameterValuesNotCapturedTest extends TestBase {

    /**
     * This test is shows an issue when we have a constructor call `BlockCipherMac(cipher,
     * macSizeInBits)` where `cipher` and `macSizeInBits` were passed as function argument, so their
     * actual value is in a function call elsewhere.
     *
     * <p>The issue is here at the level of the detection engine: neither the value of `cipher`
     * (that should be captured with a depending detection rule) or `macSizeInBits` (that should be
     * an immediate `shouldBeDetectedAs` detection) were captured.
     */
    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile("src/test/files/rules/issues/ParameterValuesNotCapturedTestFile.java")
                .withChecks(this)
                .withClassPath(BouncyCastleJars.latestJar)
                .verifyIssues();
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        /**
         * TODO: Optimally, we shouldn't have these direct detections of engines, as they appear in
         * the depending detection rules
         */
        if (findingId == 0 || findingId == 2) {
            return;
        }

        /*
         * Detection Store
         */

        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(MacContext.class);
        IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOf(ValueAction.class);
        assertThat(value0.asString()).isEqualTo("BlockCipherMac");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_1 =
                getStoreOfValueType(MacSize.class, detectionStore.getChildren());
        assertThat(store_1).isNotNull();
        assertThat(store_1.getDetectionValues()).hasSize(1);
        assertThat(store_1.getDetectionValueContext()).isInstanceOf(MacContext.class);
        IValue<Tree> value0_1 = store_1.getDetectionValues().get(0);
        assertThat(value0_1).isInstanceOf(MacSize.class);
        assertThat(value0_1.asString()).isEqualTo("128");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_2 =
                getStoreOfValueType(ValueAction.class, detectionStore.getChildren());
        assertThat(store_2).isNotNull();
        assertThat(store_2.getDetectionValues()).hasSize(1);
        assertThat(store_2.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> value0_2 = store_2.getDetectionValues().get(0);
        assertThat(value0_2).isInstanceOf(ValueAction.class);
        assertThat(value0_2.asString()).isEqualTo("AESEngine");

        /*
         * Translation
         */

        // TODO: Write it similarily to the result of `BcBlockCipherMacTest`
    }
}
