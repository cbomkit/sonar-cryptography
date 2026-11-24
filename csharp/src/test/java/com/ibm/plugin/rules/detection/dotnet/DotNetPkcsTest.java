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
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.NumberOfIterations;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.junit.jupiter.api.Test;

/**
 * Covers {@code Pkcs12Builder.SealWithMac} (HMAC, hash, iteration count) and the three {@code
 * Rfc3161TimestampRequest} factories (digest).
 *
 * <p>An unknown iteration count leaves that child off while the MAC is still reported. An unknown
 * hash gives no finding, so a finding with id 8 fails the test.
 */
class DotNetPkcsTest extends TestBase {

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/dotnet/DotNetPkcsTestFile.cs", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        assertThat(nodes).hasSize(1);
        final INode node = nodes.get(0);

        switch (findingId) {
            // SealWithMac("password", SHA256, 100000)
            case 0 -> assertMac(node, "HMAC-SHA-256", 100000);
            // a weak hash and a low count are reported as written
            case 1 -> assertMac(node, "HMAC-SHA-1", 2000);
            // iteration count from a local aliasing a const field
            case 2 -> assertMac(node, "HMAC-SHA-512", 600000);
            // keyword arguments written in the reverse of the declared order
            case 3 -> assertMac(node, "HMAC-SHA-384", 50000);
            // the three timestamp request factories
            case 4 -> assertDigest(node, "SHA-256");
            case 5 -> assertDigest(node, "SHA-384");
            case 6 -> assertDigest(node, "SHA-512");
            // iteration count is a method parameter: absent, the MAC still reported
            case 7 -> assertMac(node, "HMAC-SHA-256", null);
            default -> throw new IllegalStateException("Unexpected findingId: " + findingId);
        }
    }

    private static void assertMac(
            @Nonnull INode node,
            @Nonnull String expectedMac,
            @Nullable Integer expectedIterations) {
        assertThat(node.getKind()).isEqualTo(Mac.class);
        assertThat(node.asString()).isEqualTo(expectedMac);
        assertChild(node, NumberOfIterations.class, expectedIterations);
    }

    private static void assertDigest(@Nonnull INode node, @Nonnull String expectedDigest) {
        assertThat(node.getKind()).isEqualTo(MessageDigest.class);
        assertThat(node.asString()).isEqualTo(expectedDigest);
    }
}
