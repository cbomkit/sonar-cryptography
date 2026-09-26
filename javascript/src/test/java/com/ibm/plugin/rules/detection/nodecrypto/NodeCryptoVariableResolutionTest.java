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
                    DetectionStore<JavaScriptCheck, Tree, JavaScriptSymbol, JavaScriptScanContext>
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
