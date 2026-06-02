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
package com.ibm.plugin.rules.detection.dotnet;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.language.csharp.CSharpCheck;
import com.ibm.engine.language.csharp.CSharpScanContext;
import com.ibm.engine.language.csharp.CSharpSymbol;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.MacContext;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

class DotNetHMACTest extends TestBase {

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/dotnet/DotNetHMACTestFile.cs", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {

        /*
         * Detection Store
         */
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(MacContext.class);
        IValue<CSharpTree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOf(ValueAction.class);

        /*
         * Translation
         */
        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);
        assertThat(node.getKind()).isEqualTo(Mac.class);

        switch (findingId) {
            case 0 -> {
                assertThat(value0.asString()).isEqualTo("HMACSHA1");
                assertThat(node.asString()).isEqualTo("HMAC-SHA1");
                INode digest = node.getChildren().get(MessageDigest.class);
                assertThat(digest).isNotNull();
                assertThat(digest.asString()).isEqualTo("SHA1");
                INode digestSize = digest.getChildren().get(DigestSize.class);
                assertThat(digestSize).isNotNull();
                assertThat(digestSize.asString()).isEqualTo("160");
            }
            case 1 -> {
                assertThat(value0.asString()).isEqualTo("HMACSHA256");
                assertThat(node.asString()).isEqualTo("HMAC-SHA256");
                INode digest = node.getChildren().get(MessageDigest.class);
                assertThat(digest).isNotNull();
                assertThat(digest.asString()).isEqualTo("SHA256");
                INode digestSize = digest.getChildren().get(DigestSize.class);
                assertThat(digestSize).isNotNull();
                assertThat(digestSize.asString()).isEqualTo("256");
            }
            case 2 -> {
                assertThat(value0.asString()).isEqualTo("HMACSHA384");
                assertThat(node.asString()).isEqualTo("HMAC-SHA384");
                INode digest = node.getChildren().get(MessageDigest.class);
                assertThat(digest).isNotNull();
                assertThat(digest.asString()).isEqualTo("SHA384");
                INode digestSize = digest.getChildren().get(DigestSize.class);
                assertThat(digestSize).isNotNull();
                assertThat(digestSize.asString()).isEqualTo("384");
            }
            case 3 -> {
                assertThat(value0.asString()).isEqualTo("HMACSHA512");
                assertThat(node.asString()).isEqualTo("HMAC-SHA512");
                INode digest = node.getChildren().get(MessageDigest.class);
                assertThat(digest).isNotNull();
                assertThat(digest.asString()).isEqualTo("SHA512");
                INode digestSize = digest.getChildren().get(DigestSize.class);
                assertThat(digestSize).isNotNull();
                assertThat(digestSize.asString()).isEqualTo("512");
            }
            case 4 -> {
                assertThat(value0.asString()).isEqualTo("HMACMD5");
                assertThat(node.asString()).isEqualTo("HMAC-MD5");
                INode digest = node.getChildren().get(MessageDigest.class);
                assertThat(digest).isNotNull();
                assertThat(digest.asString()).isEqualTo("MD5");
                INode digestSize = digest.getChildren().get(DigestSize.class);
                assertThat(digestSize).isNotNull();
                assertThat(digestSize.asString()).isEqualTo("128");
            }
            default -> throw new IllegalStateException("Unexpected findingId: " + findingId);
        }
    }
}
