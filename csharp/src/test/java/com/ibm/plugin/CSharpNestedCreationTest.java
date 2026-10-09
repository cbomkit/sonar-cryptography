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
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * Covers creation sites that are not statements of their own.
 *
 * <p>All of these were previously invisible, and not only in their parameters: the whole finding
 * was lost, because the converter treated only a creation in statement position as a call site.
 * Everything else — a creation handed straight to another constructor or method, one written as an
 * object or collection initializer value, one initializing a field or an auto-property — was never
 * offered to the detection engine at all.
 *
 * <p>The shapes come from Microsoft.IdentityModel, where key registries and test data are built
 * exactly this way, for example {@code SecurityKey = new RsaSecurityKey(RSA.Create(2048))}. Each
 * case asserts the parameter as well as the algorithm, since a finding without its key size or
 * curve is only half the answer.
 */
class CSharpNestedCreationTest extends TestBase {

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/CSharpNestedCreationTestFile.cs", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        switch (findingId) {
            // The field initializer and the auto-property initializer. Both sit outside any method
            // body and reach the engine through one synthetic block per class, but each is its own
            // call site and so its own finding.
            case 0 -> assertSingleRsa(nodes, 3072);
            case 1 -> assertSingleRsa(nodes, 1024);
            // new Wrapper(RSA.Create(2048)) — handed straight to another constructor
            case 2 -> assertSingleRsa(nodes, 2048);
            // Use(RSA.Create(4096)) — handed straight to a method
            case 3 -> assertSingleRsa(nodes, 4096);
            // new Holder { Key = new Wrapper(RSA.Create(7680)) } — object-initializer value
            case 4 -> assertSingleRsa(nodes, 7680);
            // new Holder { Key = ECDsa.Create(ECCurve.NamedCurves.nistP384) }
            case 5 -> assertSingleCurve(nodes, "nistP384");
            // a collection-initializer element holding the creation
            case 6 -> assertSingleCurve(nodes, "nistP521");
            // _assigned = new Wrapper2(RSA.Create(15360)).Key — assignment to a field
            case 7 -> assertSingleRsa(nodes, 15360);
            default -> throw new IllegalStateException("Unexpected findingId: " + findingId);
        }
    }

    private static void assertSingleRsa(@Nonnull List<INode> nodes, int expectedBits) {
        assertThat(nodes).hasSize(1);
        final INode node = nodes.get(0);
        assertThat(node.asString()).isEqualTo("RSA-" + expectedBits);
        assertChild(node, KeyLength.class, expectedBits);
    }

    private static void assertSingleCurve(@Nonnull List<INode> nodes, @Nonnull String curve) {
        assertThat(nodes).hasSize(1);
        assertThat(nodes.get(0).asString()).isEqualTo("ECDSA-" + curve);
        assertChild(nodes.get(0), EllipticCurve.class, curve);
    }
}
