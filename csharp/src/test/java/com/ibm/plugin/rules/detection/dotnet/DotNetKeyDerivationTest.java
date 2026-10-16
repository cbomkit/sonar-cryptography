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
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.NumberOfIterations;
import com.ibm.mapper.model.SaltLength;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.junit.jupiter.api.Test;

/**
 * Covers the KDF family other than {@code Rfc2898DeriveBytes}: {@code HKDF}, {@code
 * SP800108HmacCounterKdf} and the legacy {@code PasswordDeriveBytes}.
 *
 * <p>Each method is exercised in its array form and, where .NET offers one, in its span form. The
 * span forms matter because they put a {@code Span<byte>} destination exactly where the array forms
 * put an {@code int} output length, at the same arity. The expectations below therefore assert an
 * output length for the array form and its <em>absence</em> for the span form, which is what proves
 * the two are told apart by parameter type rather than by position.
 *
 * <p>Two further cases carry most of the weight. One writes every argument as a keyword in the
 * reverse of the declared order, so a value landing on the wrong parameter would show up
 * immediately as a swapped salt and output length. The other takes its salt from an environment
 * variable through a helper, where the only correct answer is to report {@code HKDF} and its hash
 * and no salt length at all.
 */
class DotNetKeyDerivationTest extends TestBase {

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/dotnet/DotNetKeyDerivationTestFile.cs", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        IValue<CSharpTree> primary = detectionStore.getDetectionValues().get(0);
        assertThat(primary).isInstanceOf(ValueAction.class);
        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);

        switch (findingId) {
            // HKDF.Extract(SHA256, ikm, salt): salt is a local byte[16]
            case 0 -> assertKdf(node, "HKDF-SHA-256", "SHA-256", 128, null, null);
            // HKDF.Expand(SHA256, prk, 32, info): 32 output bytes
            case 1 -> assertKdf(node, "HKDF-SHA-256", "SHA-256", null, 256, null);
            // HKDF.DeriveKey(SHA256, ikm, 32, salt, info)
            case 2 -> assertKdf(node, "HKDF-SHA-256", "SHA-256", 128, 256, null);
            // new SP800108HmacCounterKdf(byte[32], SHA256) then kdf.DeriveKey(label, context, 32)
            case 3 -> assertKdf(node, "SP800_108_CounterKDF", "SHA-256", null, 256, null);
            // SP800108HmacCounterKdf.DeriveBytes(byte[32], SHA256, label, context, 32)
            case 4 -> assertKdf(node, "SP800_108_CounterKDF", "SHA-256", null, 256, null);
            // new PasswordDeriveBytes("password", byte[16]) then pdb.GetBytes(16)
            case 5 -> assertKdf(node, "PBKDF1", null, 128, null, null);
            // new PasswordDeriveBytes("password", byte[16], "SHA1", 100)
            case 6 -> assertKdf(node, "PBKDF1-SHA-1", "SHA-1", 128, null, 100);
            // pdb.IterationCount = 100000; pdb.HashName = "SHA256"
            case 7 -> assertKdf(node, "PBKDF1-SHA-256", "SHA-256", 128, null, 100000);
            // HKDF.Extract(SHA384, byte[32], byte[8], prk): the four-parameter span form
            case 8 -> assertKdf(node, "HKDF-SHA-384", "SHA-384", 64, null, null);
            // HKDF.Expand(SHA512, byte[32], Span output, byte[8]): a span sits where the array
            // form has outputLength, so no output length may be reported
            case 9 -> assertKdf(node, "HKDF-SHA-512", "SHA-512", null, null, null);
            // HKDF.DeriveKey(SHA256, byte[32], Span output, byte[24], byte[8]): salt still
            // readable at 24 bytes, output length still absent
            case 10 -> assertKdf(node, "HKDF-SHA-256", "SHA-256", 192, null, null);
            // every argument written as a keyword, in the reverse of the declared order
            case 11 -> assertKdf(node, "HKDF-SHA-384", "SHA-384", 160, 512, null);
            // output length through a local aliasing a const field, salt through a readonly field
            case 12 -> assertKdf(node, "HKDF-SHA-512", "SHA-512", 512, 384, null);
            // salt read from an environment variable: no salt length may be reported
            case 13 -> assertKdf(node, "HKDF-SHA-256", "SHA-256", null, 256, null);
            // SP800-108 DeriveBytes with keyword arguments out of order
            case 14 -> assertKdf(node, "SP800_108_CounterKDF", "SHA-384", null, 512, null);
            // new PasswordDeriveBytes("password", byte[16], "SHA256", 20000, null)
            case 15 -> assertKdf(node, "PBKDF1-SHA-256", "SHA-256", 128, null, 20000);
            default -> throw new IllegalStateException("Unexpected findingId: " + findingId);
        }
    }

    /** A {@code null} expectation asserts the value is absent, not that it has some default. */
    private static void assertKdf(
            @Nonnull INode node,
            @Nonnull String expectedName,
            @Nullable String expectedDigest,
            @Nullable Integer expectedSaltBits,
            @Nullable Integer expectedKeyBits,
            @Nullable Integer expectedIterations) {
        assertThat(node.asString()).isEqualTo(expectedName);
        assertChild(node, MessageDigest.class, expectedDigest);
        assertChild(node, SaltLength.class, expectedSaltBits);
        assertChild(node, KeyLength.class, expectedKeyBits);
        assertChild(node, NumberOfIterations.class, expectedIterations);
    }
}
