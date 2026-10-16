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
import com.ibm.mapper.model.PrivateKey;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * Pins the expression forms that used to hide a whole call site rather than only its parameters.
 *
 * <p>All four were found by scanning real code and asking why a call site the source plainly
 * contains produced nothing at all:
 *
 * <ul>
 *   <li>a creation inside a constructor initializer ({@code : base(new AesCryptoServiceProvider())}
 *       ), which the converter never visited — in lidgren-network-gen3 that is the only
 *       cryptography four classes have;
 *   <li>an {@code as} conversion on the result ({@code cert.GetRSAPrivateKey() as RSACng}), which
 *       the expression converter treated like a comparison and so resolved to nothing;
 *   <li>a coalescing assignment ({@code _key ??= RSA.Create(...)}), whose operator the grammar
 *       keeps on the assignment rule rather than in {@code assignment_operator}, and whose
 *       right-hand side it wraps in a {@code throwable_expression};
 *   <li>the same assignment written as an expression-bodied property, where the member's body is an
 *       assignment rather than a value.
 * </ul>
 *
 * <p>The last two cases in the fixture are the counter-checks, and they are the reason the {@code
 * as} fix is narrow: {@code candidate is RSACng} and {@code size < 2048} both yield a boolean, so
 * neither may resolve to its operand. They are asserted by the {@code default} branch below —
 * reaching it at all means something started resolving that must not.
 */
class CSharpExpressionFormsTest extends TestBase {

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/CSharpExpressionFormsTestFile.cs", this);
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
            // : base(new AesCryptoServiceProvider())
            case 0 -> assertThat(node.asString()).isEqualTo("AES");
            // : base(1, new TripleDESCryptoServiceProvider()) with no block body
            case 1 -> assertThat(node.asString()).isEqualTo("DESede");
            // certificate.GetRSAPrivateKey() as RSACng — the conversion keeps the key kind
            case 2 -> {
                assertThat(node.is(PrivateKey.class)).isTrue();
                assertThat(node.asString()).isEqualTo("RSA");
            }
            // RSA.Create(3072) as RSACng — and it keeps the parameter
            case 3 -> assertKeyLength(node, 3072);
            // _lazy ??= RSA.Create(4096)
            case 4 -> assertKeyLength(node, 4096);
            // CoalescingAssignmentAsProperty => _lazyProperty ??= RSA.Create(7680)
            case 5 -> assertKeyLength(node, 7680);
            default ->
                    throw new IllegalStateException(
                            "Unexpected findingId "
                                    + findingId
                                    + " ("
                                    + node.asString()
                                    + "): the `is` pattern and the comparison must not resolve");
        }
    }

    private static void assertKeyLength(@Nonnull INode node, int bits) {
        assertThat(node.asString()).isEqualTo("RSA-" + bits);
        assertChild(node, KeyLength.class, bits);
    }
}
