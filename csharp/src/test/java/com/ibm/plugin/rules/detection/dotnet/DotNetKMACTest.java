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
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Mac;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * Tests for {@link DotNetKMAC}.
 *
 * <p>findingId → test method → expected translated node ({@code asString()}), in source order of
 * {@code DotNetKMACTestFile.cs}:
 *
 * <ul>
 *   <li>0 → {@code TestKmac128} → {@code KMAC128}
 *   <li>1 → {@code TestKmac256} → {@code KMAC256}
 *   <li>2 → {@code TestKmacXof128} → {@code KMAC128} (raw detected value is {@code KMACXOF128}; the
 *       translated node collapses to the same {@code KMAC} model as {@code Kmac128} — see {@link
 *       DotNetKMAC} javadoc "Known modeling gap" section)
 *   <li>3 → {@code TestKmacXof256} → {@code KMAC256} (raw detected value is {@code KMACXOF256};
 *       same collapse as above, for the 256-bit pair)
 * </ul>
 */
class DotNetKMACTest extends TestBase {

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/dotnet/DotNetKMACTestFile.cs", this);
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
                assertThat(value0.asString()).isEqualTo("KMAC128");
                assertThat(node.asString()).isEqualTo("KMAC128");
            }
            case 1 -> {
                assertThat(value0.asString()).isEqualTo("KMAC256");
                assertThat(node.asString()).isEqualTo("KMAC256");
            }
            case 2 -> {
                assertThat(value0.asString()).isEqualTo("KMACXOF128");
                assertThat(node.asString()).isEqualTo("KMAC128");
            }
            case 3 -> {
                assertThat(value0.asString()).isEqualTo("KMACXOF256");
                assertThat(node.asString()).isEqualTo("KMAC256");
            }
            default -> throw new IllegalStateException("Unexpected findingId: " + findingId);
        }
    }
}
