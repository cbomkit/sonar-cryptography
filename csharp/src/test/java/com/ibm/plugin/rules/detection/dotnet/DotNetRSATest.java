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
import com.ibm.engine.model.CipherAction;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.SignatureAction;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.functionality.Decrypt;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.mapper.model.functionality.Verify;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * Comprehensive test for all RSA-related detection rules (DotNetRSA.java).
 *
 * <p>Covers all four RSA-related classes and their complete operational API surface:
 *
 * <ul>
 *   <li>RSA (abstract base)
 *   <li>RSACng, RSACryptoServiceProvider, RSAOpenSsl (derived from RSA)
 * </ul>
 *
 * <p>Finding mapping (one finding per test method in DotNetRSATestFile.cs):
 *
 * <pre>
 * Section 1 – factory methods / constructors (findings 0–4):
 *   0 TestRsaCreate              → RSA
 *   1 TestRsaCreateWithKeySize   → RSA
 *   2 TestRsaCsp                 → RSA
 *   3 TestRsaCng                 → RSA
 *   4 TestRsaOpenSsl             → RSA
 *
 * Section 2 – property KeySize setters (findings 5–6):
 *   5 TestPropertyKeySize2048    → RSA-2048
 *   6 TestPropertyKeySize4096    → RSA-4096
 *
 * Section 3 – Encrypt / Decrypt (findings 7–10):
 *   7  TestEncrypt      → RSA + Encrypt
 *   8  TestDecrypt      → RSA + Decrypt
 *   9  TestTryEncrypt   → RSA + Encrypt
 *   10 TestTryDecrypt   → RSA + Decrypt
 *
 * Section 4 – SignData / TrySignData / VerifyData (findings 11–13):
 *   11 TestSignData     → RSA + Sign
 *   12 TestTrySignData  → RSA + Sign
 *   13 TestVerifyData   → RSA + Verify
 *
 * Section 5 – SignHash / TrySignHash / VerifyHash (findings 14–16):
 *   14 TestSignHash     → RSA + Sign
 *   15 TestTrySignHash  → RSA + Sign
 *   16 TestVerifyHash   → RSA + Verify
 *
 * Section 6 – combined usage patterns (findings 17–19):
 *   17 TestRsaCngFullFlow        → RSA-3072 + Encrypt
 *   18 TestRsaCspSignFlow        → RSA + Sign
 *   19 TestRsaOpenSslVerifyFlow  → RSA + Verify
 * </pre>
 */
class DotNetRSATest extends TestBase {

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/dotnet/DotNetRSATestFile.cs", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {

        // Every top-level finding must be RSA
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(KeyContext.class);
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        IValue<CSharpTree> primary = detectionStore.getDetectionValues().get(0);
        assertThat(primary).isInstanceOf(ValueAction.class);
        assertThat(primary.asString()).isEqualTo("RSA");

        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);
        assertThat(node.getKind()).isEqualTo(PublicKeyEncryption.class);

        // RSA always carries its OID as a child node
        INode oid = node.getChildren().get(Oid.class);
        assertThat(oid).isNotNull();
        assertThat(oid.asString()).isEqualTo("1.2.840.113549.1.1.1");

        switch (findingId) {

            // -----------------------------------------------------------------
            // Section 1: simple constructors — only RSA, no children fired
            // -----------------------------------------------------------------
            case 0, 1, 2, 3, 4 -> assertThat(node.asString()).isEqualTo("RSA");

            // -----------------------------------------------------------------
            // Section 2: property KeySize setters
            // -----------------------------------------------------------------
            case 5 -> assertKeySize(detectionStore, node, "2048");
            case 6 -> assertKeySize(detectionStore, node, "4096");

            // -----------------------------------------------------------------
            // Section 3: Encrypt / Decrypt / TryEncrypt / TryDecrypt
            // -----------------------------------------------------------------
            case 7, 9 -> assertEncrypt(detectionStore, node, "RSA");
            case 8, 10 -> assertDecrypt(detectionStore, node, "RSA");

            // -----------------------------------------------------------------
            // Section 4: SignData / TrySignData / VerifyData
            // -----------------------------------------------------------------
            case 11, 12 -> assertSign(detectionStore, node, "RSA");
            case 13 -> assertVerify(detectionStore, node, "RSA");

            // -----------------------------------------------------------------
            // Section 5: SignHash / TrySignHash / VerifyHash
            // -----------------------------------------------------------------
            case 14, 15 -> assertSign(detectionStore, node, "RSA");
            case 16 -> assertVerify(detectionStore, node, "RSA");

            // -----------------------------------------------------------------
            // Section 6: combined usage patterns
            // -----------------------------------------------------------------
            case 17 -> assertEncrypt(detectionStore, node, "RSA-3072");
            case 18 -> assertSign(detectionStore, node, "RSA");
            case 19 -> assertVerify(detectionStore, node, "RSA");

            default -> throw new IllegalStateException("Unexpected findingId: " + findingId);
        }
    }

    // -------------------------------------------------------------------------
    // Assertion helpers
    // -------------------------------------------------------------------------

    private void assertKeySize(
            @Nonnull DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> store,
            @Nonnull INode node,
            @Nonnull String expectedKeySize) {

        assertThat(node.asString()).isEqualTo("RSA-" + expectedKeySize);
        assertThat(node.getChildren().get(KeyLength.class)).isNotNull();
        assertThat(node.getChildren().get(KeyLength.class).asString()).isEqualTo(expectedKeySize);
    }

    private void assertEncrypt(
            @Nonnull DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> store,
            @Nonnull INode node,
            @Nonnull String expectedNodeString) {

        DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> encryptStore =
                getStoreOfValueType(CipherAction.class, store.getChildren());
        assertThat(encryptStore).isNotNull();
        assertThat(encryptStore.getDetectionValues()).hasSize(1);
        assertThat(encryptStore.getDetectionValues().get(0).asString()).isEqualTo("ENCRYPT");

        assertThat(node.asString()).isEqualTo(expectedNodeString);
        assertThat(node.getChildren().get(Encrypt.class)).isNotNull();
    }

    private void assertDecrypt(
            @Nonnull DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> store,
            @Nonnull INode node,
            @Nonnull String expectedNodeString) {

        DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> decryptStore =
                getStoreOfValueType(CipherAction.class, store.getChildren());
        assertThat(decryptStore).isNotNull();
        assertThat(decryptStore.getDetectionValues()).hasSize(1);
        assertThat(decryptStore.getDetectionValues().get(0).asString()).isEqualTo("DECRYPT");

        assertThat(node.asString()).isEqualTo(expectedNodeString);
        assertThat(node.getChildren().get(Decrypt.class)).isNotNull();
    }

    private void assertSign(
            @Nonnull DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> store,
            @Nonnull INode node,
            @Nonnull String expectedNodeString) {

        DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> signStore =
                getStoreOfValueType(SignatureAction.class, store.getChildren());
        assertThat(signStore).isNotNull();
        assertThat(signStore.getDetectionValues()).hasSize(1);
        assertThat(signStore.getDetectionValues().get(0).asString()).isEqualTo("SIGN");

        assertThat(node.asString()).isEqualTo(expectedNodeString);
        assertThat(node.getChildren().get(Sign.class)).isNotNull();
    }

    private void assertVerify(
            @Nonnull DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> store,
            @Nonnull INode node,
            @Nonnull String expectedNodeString) {

        DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> verifyStore =
                getStoreOfValueType(SignatureAction.class, store.getChildren());
        assertThat(verifyStore).isNotNull();
        assertThat(verifyStore.getDetectionValues()).hasSize(1);
        assertThat(verifyStore.getDetectionValues().get(0).asString()).isEqualTo("VERIFY");

        assertThat(node.asString()).isEqualTo(expectedNodeString);
        assertThat(node.getChildren().get(Verify.class)).isNotNull();
    }
}
