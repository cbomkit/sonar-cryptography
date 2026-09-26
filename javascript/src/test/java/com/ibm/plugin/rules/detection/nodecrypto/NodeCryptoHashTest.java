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
import com.ibm.engine.model.context.MacContext;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.functionality.Digest;
import com.ibm.plugin.TestBase;
import com.ibm.plugin.javascript.api.JavaScriptCheck;
import com.ibm.plugin.javascript.api.JavaScriptSymbol;
import com.ibm.plugin.javascript.api.Tree;
import com.ibm.plugin.javascript.language.JavaScriptScanContext;
import com.ibm.plugin.testing.JavaScriptVerifier;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

class NodeCryptoHashTest extends TestBase {

    @Test
    void testCreateHashAndHmac() throws Exception {
        JavaScriptVerifier.verify("rules/detection/nodecrypto/NodeCryptoHashTestFile.js", this);
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
            assertThat(value.asString()).isEqualToIgnoringCase("md5");

            assertThat(nodes).hasSize(1);
            INode messageDigestNode = nodes.get(0);
            assertThat(messageDigestNode.getKind()).isEqualTo(MessageDigest.class);
            assertThat(messageDigestNode.asString()).isEqualToIgnoringCase("MD5");
            assertThat(messageDigestNode.getChildren().get(Digest.class)).isNotNull();
            assertThat(messageDigestNode.getChildren().get(BlockSize.class)).isNotNull();
            assertThat(messageDigestNode.getChildren().get(DigestSize.class)).isNotNull();
        } else if (findingId == 1) {
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(MacContext.class);
            assertThat(detectionStore.getDetectionValues()).hasSizeGreaterThanOrEqualTo(1);
            assertThat(
                            detectionStore.getDetectionValues().stream()
                                    .anyMatch(v -> v instanceof Algorithm))
                    .isTrue();
            assertThat(nodes).hasSize(1);
            assertThat(nodes.get(0).getKind()).isEqualTo(Mac.class);
        }
    }
}
