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
import com.ibm.mapper.model.MaskGenerationFunction;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.Signature;
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
 * Test for the legacy Formatter/Deformatter and mask-generation detection rules
 * (DotNetLegacyFormatters.java).
 *
 * <p>Finding mapping (one finding per test method in DotNetLegacyFormattersTestFile.cs; the
 * parameterless constructor overload is used throughout, so — unlike DotNetRSATest/DotNetDSATest —
 * no extra findings from DSA.Create()/RSA.Create() are interleaved):
 *
 * <pre>
 * 0  TestDsaSignatureFormatterCreateSignature          → DSA + Sign
 * 1  TestDsaSignatureFormatterSetHashAlgorithm         → DSA-SHA-1 + MessageDigest(SHA-1)
 * 2  TestDsaSignatureDeformatterVerifySignature        → DSA + Verify
 * 3  TestRsaPkcs1SignatureFormatterCreateSignature     → RSA + Sign
 * 4  TestRsaPkcs1SignatureFormatterSetHashAlgorithm    → RSA + MessageDigest(SHA-256)
 * 5  TestRsaPkcs1SignatureDeformatterVerifySignature   → RSA + Verify
 * 6  TestRsaOaepKeyExchangeFormatterCreateKeyExchange1 → RSA-OAEP + Encrypt + Padding(OAEP)
 * 7  TestRsaOaepKeyExchangeFormatterCreateKeyExchange2 → RSA-OAEP + Encrypt + Padding(OAEP)
 * 8  TestRsaOaepKeyExchangeDeformatterDecryptKeyExchange → RSA-OAEP + Decrypt + Padding(OAEP)
 * 9  TestRsaPkcs1KeyExchangeFormatterCreateKeyExchange1  → RSA + Encrypt + Padding(PKCS1)
 * 10 TestRsaPkcs1KeyExchangeFormatterCreateKeyExchange2  → RSA + Encrypt + Padding(PKCS1)
 * 11 TestRsaPkcs1KeyExchangeDeformatterDecryptKeyExchange → RSA + Decrypt + Padding(PKCS1)
 * 12 TestPkcs1MaskGenerationMethodCreate                → MGF1
 * 13 TestPkcs1MaskGenerationMethodSetHashName           → MGF1 + MessageDigest(SHA-256)
 * </pre>
 *
 * These node-string / OID values were captured by first running this test with a no-op {@code
 * asserts()} and inspecting {@code target/node-tree.log}, per the project's testing guidelines
 * (never guessing {@code asString()} output).
 */
class DotNetLegacyFormattersTest extends TestBase {

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/dotnet/DotNetLegacyFormattersTestFile.cs", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {

        // Every top-level finding in this file is a KeyContext ValueAction (DSA/RSA/MGF1)
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(KeyContext.class);
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        IValue<CSharpTree> primary = detectionStore.getDetectionValues().get(0);
        assertThat(primary).isInstanceOf(ValueAction.class);

        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);

        switch (findingId) {
            case 0 -> {
                assertThat(primary.asString()).isEqualTo("DSA");
                assertThat(node.getKind()).isEqualTo(Signature.class);
                assertThat(node.asString()).isEqualTo("DSA");
                assertOid(node, "1.2.840.10040.4.1");
                assertSign(detectionStore, node);
            }
            case 1 -> {
                assertThat(primary.asString()).isEqualTo("DSA");
                assertThat(node.getKind()).isEqualTo(Signature.class);
                assertThat(node.asString()).isEqualTo("DSA-SHA-1");
                assertOid(node, "1.2.840.10040.4.3");
                assertDigest(node, "SHA-1");
            }
            case 2 -> {
                assertThat(primary.asString()).isEqualTo("DSA");
                assertThat(node.getKind()).isEqualTo(Signature.class);
                assertThat(node.asString()).isEqualTo("DSA");
                assertOid(node, "1.2.840.10040.4.1");
                assertVerify(detectionStore, node);
            }
            case 3 -> {
                assertThat(primary.asString()).isEqualTo("RSA");
                assertThat(node.getKind()).isEqualTo(PublicKeyEncryption.class);
                assertThat(node.asString()).isEqualTo("RSA");
                assertOid(node, "1.2.840.113549.1.1.1");
                assertSign(detectionStore, node);
            }
            case 4 -> {
                assertThat(primary.asString()).isEqualTo("RSA");
                assertThat(node.getKind()).isEqualTo(PublicKeyEncryption.class);
                assertThat(node.asString()).isEqualTo("RSA");
                assertOid(node, "1.2.840.113549.1.1.1");
                assertDigest(node, "SHA-256");
            }
            case 5 -> {
                assertThat(primary.asString()).isEqualTo("RSA");
                assertThat(node.getKind()).isEqualTo(PublicKeyEncryption.class);
                assertThat(node.asString()).isEqualTo("RSA");
                assertOid(node, "1.2.840.113549.1.1.1");
                assertVerify(detectionStore, node);
            }
            case 6, 7 -> {
                assertThat(primary.asString()).isEqualTo("RSA");
                assertThat(node.getKind()).isEqualTo(PublicKeyEncryption.class);
                assertThat(node.asString()).isEqualTo("RSA-OAEP");
                assertOid(node, "1.2.840.113549.1.1.7");
                assertPadding(node, "OAEP");
                assertEncrypt(detectionStore, node);
            }
            case 8 -> {
                assertThat(primary.asString()).isEqualTo("RSA");
                assertThat(node.getKind()).isEqualTo(PublicKeyEncryption.class);
                assertThat(node.asString()).isEqualTo("RSA-OAEP");
                assertOid(node, "1.2.840.113549.1.1.7");
                assertPadding(node, "OAEP");
                assertDecrypt(detectionStore, node);
            }
            case 9, 10 -> {
                assertThat(primary.asString()).isEqualTo("RSA");
                assertThat(node.getKind()).isEqualTo(PublicKeyEncryption.class);
                assertThat(node.asString()).isEqualTo("RSA");
                assertOid(node, "1.2.840.113549.1.1.1");
                assertPadding(node, "PKCS1");
                assertEncrypt(detectionStore, node);
            }
            case 11 -> {
                assertThat(primary.asString()).isEqualTo("RSA");
                assertThat(node.getKind()).isEqualTo(PublicKeyEncryption.class);
                assertThat(node.asString()).isEqualTo("RSA");
                assertOid(node, "1.2.840.113549.1.1.1");
                assertPadding(node, "PKCS1");
                assertDecrypt(detectionStore, node);
            }
            case 12 -> {
                assertThat(primary.asString()).isEqualTo("MGF1");
                assertThat(node.getKind()).isEqualTo(MaskGenerationFunction.class);
                assertThat(node.asString()).isEqualTo("MGF1");
                assertOid(node, "1.2.840.113549.1.1.8");
            }
            case 13 -> {
                assertThat(primary.asString()).isEqualTo("MGF1");
                assertThat(node.getKind()).isEqualTo(MaskGenerationFunction.class);
                assertThat(node.asString()).isEqualTo("MGF1");
                assertOid(node, "1.2.840.113549.1.1.8");
                assertDigest(node, "SHA-256");
            }
            default -> throw new IllegalStateException("Unexpected findingId: " + findingId);
        }
    }

    // -------------------------------------------------------------------------
    // Assertion helpers
    // -------------------------------------------------------------------------

    private void assertOid(@Nonnull INode node, @Nonnull String expectedOid) {
        INode oid = node.getChildren().get(Oid.class);
        assertThat(oid).isNotNull();
        assertThat(oid.asString()).isEqualTo(expectedOid);
    }

    private void assertDigest(@Nonnull INode node, @Nonnull String expectedDigest) {
        INode digest = node.getChildren().get(MessageDigest.class);
        assertThat(digest).isNotNull();
        assertThat(digest.asString()).isEqualTo(expectedDigest);
    }

    private void assertPadding(@Nonnull INode node, @Nonnull String expectedPadding) {
        INode padding = node.getChildren().get(Padding.class);
        assertThat(padding).isNotNull();
        assertThat(padding.asString()).isEqualTo(expectedPadding);
    }

    private void assertSign(
            @Nonnull DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> store,
            @Nonnull INode node) {
        DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> signStore =
                getStoreOfValueType(SignatureAction.class, store.getChildren());
        assertThat(signStore).isNotNull();
        assertThat(signStore.getDetectionValues()).hasSize(1);
        assertThat(signStore.getDetectionValues().get(0).asString()).isEqualTo("SIGN");
        assertThat(node.getChildren().get(Sign.class)).isNotNull();
    }

    private void assertVerify(
            @Nonnull DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> store,
            @Nonnull INode node) {
        DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> verifyStore =
                getStoreOfValueType(SignatureAction.class, store.getChildren());
        assertThat(verifyStore).isNotNull();
        assertThat(verifyStore.getDetectionValues()).hasSize(1);
        assertThat(verifyStore.getDetectionValues().get(0).asString()).isEqualTo("VERIFY");
        assertThat(node.getChildren().get(Verify.class)).isNotNull();
    }

    private void assertEncrypt(
            @Nonnull DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> store,
            @Nonnull INode node) {
        // The CipherAction and the constant Padding value (see DotNetLegacyFormatters's
        // CREATE_KEY_EXCHANGE_* rules) are captured by the same rule/level, so this child store's
        // detection values contains both — unlike DotNetRSA's plain Encrypt/Decrypt rules.
        DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> encryptStore =
                getStoreOfValueType(CipherAction.class, store.getChildren());
        assertThat(encryptStore).isNotNull();
        assertThat(encryptStore.getDetectionValues())
                .anyMatch(value -> "ENCRYPT".equals(value.asString()));
        assertThat(node.getChildren().get(Encrypt.class)).isNotNull();
    }

    private void assertDecrypt(
            @Nonnull DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> store,
            @Nonnull INode node) {
        DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> decryptStore =
                getStoreOfValueType(CipherAction.class, store.getChildren());
        assertThat(decryptStore).isNotNull();
        assertThat(decryptStore.getDetectionValues())
                .anyMatch(value -> "DECRYPT".equals(value.asString()));
        assertThat(node.getChildren().get(Decrypt.class)).isNotNull();
    }
}
