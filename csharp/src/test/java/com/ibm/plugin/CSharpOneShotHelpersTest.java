/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2026 PQCA
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
package com.ibm.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.language.csharp.CSharpCheck;
import com.ibm.engine.language.csharp.CSharpScanContext;
import com.ibm.engine.language.csharp.CSharpSymbol;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.MessageDigest;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * Covers the static one-shot helpers {@code HashData} and {@code TryHashData}.
 *
 * <p>These were previously not detected at all. The rule set treated every operation method of
 * {@code HashAlgorithm} as adding nothing over the creation call, which holds for {@code
 * instance.ComputeHash(data)} but not for a one-shot: it has no creation call to add to. Since .NET
 * 5 it is also the recommended way to hash, so in the local corpus 8 of the 14 files using one had
 * no {@code Create} call anywhere and reported no algorithm.
 */
class CSharpOneShotHelpersTest extends TestBase {

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/CSharpOneShotHelpersTestFile.cs", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);

        switch (findingId) {
            case 0 -> assertThat(node.asString()).isEqualTo("SHA-256");
            case 1 -> assertThat(node.asString()).isEqualTo("SHA-384");
            case 2 -> assertThat(node.asString()).isEqualTo("SHA-512");
            case 3 -> assertThat(node.asString()).isEqualTo("SHA-1");
            case 4 -> assertThat(node.asString()).isEqualTo("MD5");
            // SHA256.TryHashData(d, dest, out written)
            case 5 -> assertThat(node.asString()).isEqualTo("SHA-256");
            // HMACSHA256.HashData(new byte[32], d): a 256-bit key stated at the call site
            case 6 -> {
                assertThat(node.asString()).isEqualTo("HMAC-SHA-256");
                assertChild(node, MessageDigest.class, "SHA-256");
                assertChild(node, KeyLength.class, 256);
            }
            // HMACSHA512.HashData(key, d) with a key read from the environment: the MAC is
            // reported, the key length must not be
            case 7 -> {
                assertThat(node.asString()).isEqualTo("HMAC-SHA-512");
                assertChild(node, MessageDigest.class, "SHA-512");
                assertNoChild(node, KeyLength.class);
            }
            default -> throw new IllegalStateException("Unexpected findingId: " + findingId);
        }
    }
}
