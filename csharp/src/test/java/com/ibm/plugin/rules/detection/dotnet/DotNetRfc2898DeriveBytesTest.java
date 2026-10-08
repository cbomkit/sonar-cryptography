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
import com.ibm.engine.model.context.KeyContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.NumberOfIterations;
import com.ibm.mapper.model.PasswordBasedKeyDerivationFunction;
import com.ibm.mapper.model.SaltLength;
import com.ibm.mapper.model.functionality.KeyDerivation;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.junit.jupiter.api.Test;

/**
 * Covers every {@code Rfc2898DeriveBytes} shape the rule set claims: the constructor at each of its
 * three arities, the {@code int saltSize} overload as well as the {@code byte[] salt} one, values
 * arriving through {@code const} fields and locals, keyword arguments written out of order, both
 * five-parameter layouts of the static {@code Pbkdf2}, the two instance operations, and two cases
 * whose values are genuinely unknowable.
 *
 * <p>The last two are the ones that matter most. A parameter whose callers disagree and a salt
 * produced by a call this engine cannot see into must both leave the derived value absent while the
 * {@code PBKDF2} algorithm itself is still reported. Asserting their absence is what keeps the rule
 * set honest: a guessed iteration count would be worse than none.
 */
class DotNetRfc2898DeriveBytesTest extends TestBase {

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/dotnet/DotNetRfc2898DeriveBytesTestFile.cs", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(KeyContext.class);
        IValue<CSharpTree> primary = detectionStore.getDetectionValues().get(0);
        assertThat(primary).isInstanceOf(ValueAction.class);
        assertThat(primary.asString()).isEqualTo("PBKDF2");

        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);
        assertThat(node.getKind()).isEqualTo(PasswordBasedKeyDerivationFunction.class);

        switch (findingId) {
            // new Rfc2898DeriveBytes("password", new byte[16], 10000, HashAlgorithmName.SHA256)
            case 0 -> assertPbkdf2(node, "SHA-256", 128, 10000, null);
            // arity three, no hash argument
            case 1 -> assertPbkdf2(node, null, 64, 1000, null);
            // arity two, salt only
            case 2 -> assertPbkdf2(node, null, 256, null, null);
            // the (string password, int saltSize, int iterations, HashAlgorithmName) overload:
            // saltSize 24 must read as 192 bits of salt, exactly as a byte[24] would
            case 3 -> assertPbkdf2(node, "SHA-512", 192, 5000, null);
            // salt from a readonly field, iteration count from a local aliasing a const field
            case 4 -> assertPbkdf2(node, "SHA-384", 128, 210000, null);
            // keyword arguments written hashAlgorithm, iterations, salt — the reverse of the
            // declared order. Each value must land on the parameter it was written for.
            case 5 -> assertPbkdf2(node, "SHA-256", 128, 100000, null);
            // Pbkdf2(password, salt, iterations, hashAlgorithm, outputLength): 32 output bytes
            case 6 -> assertPbkdf2(node, "SHA-256", 128, 10000, 256);
            // the same layout with salt, iterations and output length from const fields
            case 7 -> assertPbkdf2(node, "SHA-256", 128, 210000, 256);
            // Pbkdf2(password, salt, destination, iterations, hashAlgorithm): the second layout.
            // iterations and hashAlgorithm sit two positions further right than in the first
            // layout, so they can only be placed by type. outputLength has no counterpart here and
            // must stay absent rather than be filled from the iteration count.
            case 8 -> assertPbkdf2(node, "SHA-384", 128, 150000, null);
            // constructor followed by kdf.GetBytes(32)
            case 9 -> {
                assertPbkdf2(node, "SHA-256", 128, 10000, null);
                assertKeyDerivationChild(detectionStore, node);
            }
            // constructor followed by kdf.CryptDeriveKey("TripleDES", "SHA1", 192, iv)
            case 10 -> {
                assertPbkdf2(node, "SHA-256", 128, 10000, null);
                assertKeyDerivationChild(detectionStore, node);
            }
            // iteration count is a method parameter whose two callers pass different values, so no
            // iteration count may be reported
            case 11 -> assertPbkdf2(node, "SHA-256", 128, null, null);
            // salt comes from a helper that reads the environment, so no salt length may be
            // reported
            case 12 -> assertPbkdf2(node, "SHA-256", null, 30000, null);
            default -> throw new IllegalStateException("Unexpected findingId: " + findingId);
        }
    }

    /**
     * Asserts the four parameters of a PBKDF2 node, where {@code null} means the value must be
     * absent rather than present with some default.
     */
    private static void assertPbkdf2(
            @Nonnull INode node,
            @Nullable String expectedDigest,
            @Nullable Integer expectedSaltBits,
            @Nullable Integer expectedIterations,
            @Nullable Integer expectedKeyBits) {
        assertChild(node, MessageDigest.class, expectedDigest);
        assertChild(
                node,
                SaltLength.class,
                expectedSaltBits == null ? null : String.valueOf(expectedSaltBits));
        assertChild(
                node,
                NumberOfIterations.class,
                expectedIterations == null ? null : String.valueOf(expectedIterations));
        assertChild(
                node,
                KeyLength.class,
                expectedKeyBits == null ? null : String.valueOf(expectedKeyBits));
    }

    private void assertKeyDerivationChild(
            @Nonnull DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> store,
            @Nonnull INode node) {
        DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> deriveStore =
                getStoreOfValueType(ValueAction.class, store.getChildren());
        assertThat(deriveStore).isNotNull();

        assertThat(node.getChildren().get(KeyDerivation.class)).isNotNull();
        assertThat(node.getChildren().get(KeyDerivation.class).asString())
                .isEqualTo("KEYDERIVATION");
    }
}
