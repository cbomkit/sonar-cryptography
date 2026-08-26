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
import com.ibm.engine.model.context.DigestContext;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.ExtendableOutputFunction;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.ParameterSetIdentifier;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * Tests for {@link DotNetSHA3}, covering:
 *
 * <ul>
 *   <li>findingId 0 → {@code TestSha3_256Create} → {@code SHA3-256}
 *   <li>findingId 1 → {@code TestSha3_384Create} → {@code SHA3-384}
 *   <li>findingId 2 → {@code TestSha3_512Create} → {@code SHA3-512}
 *   <li>findingId 3 → {@code TestShake128} → {@code SHAKE128}
 *   <li>findingId 4 → {@code TestShake256} → {@code SHAKE256}
 * </ul>
 */
class DotNetSHA3Test extends TestBase {

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/dotnet/DotNetSHA3TestFile.cs", this);
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
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(DigestContext.class);
        IValue<CSharpTree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOf(ValueAction.class);

        /*
         * Translation
         */
        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);

        switch (findingId) {
            case 0 -> {
                assertThat(value0.asString()).isEqualTo("SHA3_256");
                assertThat(node.getKind()).isEqualTo(MessageDigest.class);
                assertThat(node.asString()).isEqualTo("SHA3-256");
                INode digestSize = node.getChildren().get(DigestSize.class);
                assertThat(digestSize).isNotNull();
                assertThat(digestSize.asString()).isEqualTo("256");
            }
            case 1 -> {
                assertThat(value0.asString()).isEqualTo("SHA3_384");
                assertThat(node.getKind()).isEqualTo(MessageDigest.class);
                assertThat(node.asString()).isEqualTo("SHA3-384");
                INode digestSize = node.getChildren().get(DigestSize.class);
                assertThat(digestSize).isNotNull();
                assertThat(digestSize.asString()).isEqualTo("384");
            }
            case 2 -> {
                assertThat(value0.asString()).isEqualTo("SHA3_512");
                assertThat(node.getKind()).isEqualTo(MessageDigest.class);
                assertThat(node.asString()).isEqualTo("SHA3-512");
                INode digestSize = node.getChildren().get(DigestSize.class);
                assertThat(digestSize).isNotNull();
                assertThat(digestSize.asString()).isEqualTo("512");
            }
            case 3 -> {
                assertThat(value0.asString()).isEqualTo("Shake128");
                assertThat(node.getKind()).isEqualTo(ExtendableOutputFunction.class);
                assertThat(node.asString()).isEqualTo("SHAKE128");
                INode parameterSetIdentifier = node.getChildren().get(ParameterSetIdentifier.class);
                assertThat(parameterSetIdentifier).isNotNull();
                assertThat(parameterSetIdentifier.asString()).isEqualTo("128");
            }
            case 4 -> {
                assertThat(value0.asString()).isEqualTo("Shake256");
                assertThat(node.getKind()).isEqualTo(ExtendableOutputFunction.class);
                assertThat(node.asString()).isEqualTo("SHAKE256");
                INode parameterSetIdentifier = node.getChildren().get(ParameterSetIdentifier.class);
                assertThat(parameterSetIdentifier).isNotNull();
                assertThat(parameterSetIdentifier.asString()).isEqualTo("256");
            }
            default -> throw new IllegalStateException("Unexpected findingId: " + findingId);
        }
    }
}
