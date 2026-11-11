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
 * Covers the conversion of a chained property assignment, {@code a.b.c = value}, to a setter whose
 * receiver is the whole chain.
 *
 * <p>The chain must not be attributed to the root variable: {@code rsa.Options.KeySize = 4096}
 * gives {@code rsa} no key length. A single-level setter still attaches, a deeper chain is
 * converted, and a chain with an index is not, so no finding with id 3 appears.
 */
class CSharpChainedSetterTest extends TestBase {

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/CSharpChainedSetterTestFile.cs", this);
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
            // rsa.Options.KeySize = 4096: not attributed to rsa, so no key length
            case 0 -> {
                assertThat(node.asString()).isEqualTo("RSA");
                assertNoChild(node, KeyLength.class);
            }
            // rsa.KeySize = 2048: still attributed
            case 1 -> {
                assertThat(node.asString()).isEqualTo("RSA-2048");
                assertChild(node, KeyLength.class, 2048);
            }
            // signedXml.Outer.Inner.DigestMethod = SignedXml.XmlDsigSHA256Url
            case 2 -> {
                assertThat(node.getKind()).isEqualTo(MessageDigest.class);
                assertThat(node.asString()).isEqualTo("SHA-256");
            }
            // signedXml.SignedInfo!.SignatureMethod: the `!` must not break the chain
            case 3 -> assertThat(node.asString()).isEqualTo("RSA-PKCS1-1.5-SHA-1");
            default -> throw new IllegalStateException("Unexpected findingId: " + findingId);
        }
    }
}
