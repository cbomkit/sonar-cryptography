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
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Mac;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.junit.jupiter.api.Test;

/**
 * Tests for the KMAC detection rules.
 *
 * <p>Each case asserts the algorithm the rule reports, the mapper node it translates to, and the
 * MAC key length. The XOF variants translate to the same node as their fixed-output siblings, which
 * is why the reported value and the node name differ for two of them.
 *
 * <p>The last case takes its key from an environment variable, where the only correct answer is the
 * algorithm with no key length at all.
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
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(MacContext.class);
        IValue<CSharpTree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOf(ValueAction.class);

        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);
        assertThat(node.getKind()).isEqualTo(Mac.class);

        switch (findingId) {
            // new Kmac128(byte[16])
            case 0 -> assertKmac(value0, node, "KMAC128", "KMAC128", 128);
            // new Kmac256(byte[32])
            case 1 -> assertKmac(value0, node, "KMAC256", "KMAC256", 256);
            // new KmacXof128(byte[16])
            case 2 -> assertKmac(value0, node, "KMACXOF128", "KMAC128", 128);
            // new KmacXof256(byte[32])
            case 3 -> assertKmac(value0, node, "KMACXOF256", "KMAC256", 256);
            // new Kmac256(byte[48], byte[8]): the customization string carries no length
            case 4 -> assertKmac(value0, node, "KMAC256", "KMAC256", 384);
            // new Kmac128(key: byte[20]) by keyword
            case 5 -> assertKmac(value0, node, "KMAC128", "KMAC128", 160);
            // new Kmac128(key) where key comes from the environment
            case 6 -> assertKmac(value0, node, "KMAC128", "KMAC128", null);
            default -> throw new IllegalStateException("Unexpected findingId: " + findingId);
        }
    }

    /** A {@code null} key length asserts absence, not a default. */
    private static void assertKmac(
            @Nonnull IValue<CSharpTree> value,
            @Nonnull INode node,
            @Nonnull String expectedValue,
            @Nonnull String expectedNode,
            @Nullable Integer expectedKeyBits) {
        assertThat(value.asString()).isEqualTo(expectedValue);
        assertThat(node.asString()).isEqualTo(expectedNode);
        assertChild(node, KeyLength.class, expectedKeyBits);
    }
}
