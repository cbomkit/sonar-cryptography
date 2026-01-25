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
package com.ibm.plugin.rules.detection.gocrypto;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.language.go.GoScanContext;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.go.symbols.Symbol;
import org.sonar.go.testing.GoVerifier;
import org.sonar.plugins.go.api.Tree;
import org.sonar.plugins.go.api.checks.GoCheck;

class GoCryptoSHA3Test extends TestBase {

    public GoCryptoSHA3Test() {
        super(GoCryptoSHA3.rules());
    }

    @Test
    void test() {
        GoVerifier.verify("rules/detection/gocrypto/GoCryptoSHA3TestFile.go", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<GoCheck, Tree, Symbol, GoScanContext> detectionStore,
            @Nonnull List<INode> nodes) {
        /*
         * Detection Store
         */
        assertThat(detectionStore).isNotNull();
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(DigestContext.class);
        IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOf(ValueAction.class);

        /*
         * Translation
         */
        assertThat(nodes).hasSize(1);
        INode digestNode = nodes.get(0);
        assertThat(digestNode.getKind()).isEqualTo(MessageDigest.class);

        switch (findingId) {
            case 0 -> {
                // sha3.New256()
                assertThat(value0.asString()).isEqualTo("SHA3-256");
                assertThat(digestNode.asString()).isEqualTo("SHA-3-256");
            }
            case 1 -> {
                // sha3.New512()
                assertThat(value0.asString()).isEqualTo("SHA3-512");
                assertThat(digestNode.asString()).isEqualTo("SHA-3-512");
            }
            case 2 -> {
                // sha3.Sum256()
                assertThat(value0.asString()).isEqualTo("SHA3-256");
                assertThat(digestNode.asString()).isEqualTo("SHA-3-256");
            }
            default -> throw new IllegalStateException("Unexpected findingId: " + findingId);
        }
    }
}
