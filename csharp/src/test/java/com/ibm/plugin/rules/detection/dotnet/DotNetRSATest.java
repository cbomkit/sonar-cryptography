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
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.functionality.Decrypt;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.mapper.model.functionality.Verify;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.junit.jupiter.api.Test;

/**
 * Comprehensive test for the RSA detection rules, covering {@code RSA}, {@code
 * RSACryptoServiceProvider}, {@code RSACng} and {@code RSAOpenSsl}.
 *
 * <p>Every RSA operation in .NET names its padding, and every signing operation also names its
 * hash, so an RSA component that records neither is an incomplete one. The cases below assert both
 * on each operation: the encryption padding of {@code Encrypt} and {@code Decrypt}, and the digest
 * together with the signature padding of the six signing and verification methods.
 *
 * <p>Padding is worth asserting precisely rather than by presence. {@code
 * RSAEncryptionPadding.OaepSHA256} and {@code OaepSHA512} are the same scheme with different
 * digests, and the digest is kept on the OAEP node, so the cases distinguish them. {@code
 * RSASignaturePadding.Pkcs1} and {@code Pss} are different schemes with very different standing.
 *
 * <p>Three cases prove the values are placed by type rather than by position, which matters because
 * .NET moves the hash and padding from indices one and two in {@code SignData(data, hashAlgorithm,
 * padding)} to indices three and four in {@code SignData(data, offset, count, hashAlgorithm,
 * padding)}, and to four and five in the six-parameter {@code VerifyData}. A fourth writes both as
 * keyword arguments in reverse order.
 *
 * <p>Two cases must resolve to nothing: a padding returned by a helper method, and a hash arriving
 * as a method parameter whose two callers pass different values. In the latter the padding is a
 * literal and must still be reported, which shows that one unresolvable parameter does not take the
 * resolvable ones down with it.
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
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(KeyContext.class);
        IValue<CSharpTree> primary =
                detectionStore.getDetectionValues().stream()
                        .filter(ValueAction.class::isInstance)
                        .findFirst()
                        .orElseThrow();
        assertThat(primary.asString()).isEqualTo("RSA");

        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);
        assertThat(node.getKind()).isEqualTo(PublicKeyEncryption.class);

        INode oid = node.getChildren().get(Oid.class);
        assertThat(oid).isNotNull();
        assertThat(oid.asString()).isEqualTo("1.2.840.113549.1.1.1");

        switch (findingId) {
            // RSA.Create() and the three parameterless constructors
            case 0, 2, 3, 4 -> assertKeySize(node, null);
            // RSA.Create(2048)
            case 1 -> assertKeySize(node, 2048);
            // rsa.KeySize = 2048 / = 4096
            case 5 -> assertKeySize(node, 2048);
            case 6 -> assertKeySize(node, 4096);
            // Encrypt / Decrypt with RSAEncryptionPadding.OaepSHA256
            case 7 -> assertOperation(node, Encrypt.class, "OAEP", "SHA-256");
            case 8 -> assertOperation(node, Decrypt.class, "OAEP", "SHA-256");
            // TryEncrypt / TryDecrypt with RSAEncryptionPadding.Pkcs1
            case 9 -> assertOperation(node, Encrypt.class, "PKCS1", null);
            case 10 -> assertOperation(node, Decrypt.class, "PKCS1", null);
            // SignData / TrySignData / VerifyData with SHA256 and Pkcs1
            case 11, 12 -> assertOperation(node, Sign.class, "PKCS1", "SHA-256");
            case 13 -> assertOperation(node, Verify.class, "PKCS1", "SHA-256");
            // SignHash / TrySignHash / VerifyHash: these name the hash too
            case 14, 15 -> assertOperation(node, Sign.class, "PKCS1", "SHA-256");
            case 16 -> assertOperation(node, Verify.class, "PKCS1", "SHA-256");
            // new RSACng(3072) followed by Encrypt with OaepSHA256
            case 17 -> {
                assertKeySize(node, 3072);
                assertOperation(node, Encrypt.class, "OAEP", "SHA-256");
            }
            case 18 -> assertOperation(node, Sign.class, "PKCS1", "SHA-256");
            case 19 -> assertOperation(node, Verify.class, "PKCS1", "SHA-256");
            // single-argument constructor overloads carrying a key size
            case 20 -> assertKeySize(node, 3072);
            case 21 -> assertKeySize(node, 4096);
            case 22 -> assertKeySize(node, 2048);
            // RSA.Create(keySize) inside a for loop with a using declaration, the real
            // Bitwarden pattern
            case 23 -> assertKeySize(node, 2048);
            // SignData(data, 0, 32, SHA384, Pss): hash and padding at indices three and four
            case 24 -> assertOperation(node, Sign.class, "PSS", "SHA-384");
            // VerifyData(data, 0, 32, signature, SHA384, Pkcs1): the six-parameter form
            case 25 -> assertOperation(node, Verify.class, "PKCS1", "SHA-384");
            // SignData(data, padding: Pss, hashAlgorithm: SHA512): keywords in reverse order
            case 26 -> assertOperation(node, Sign.class, "PSS", "SHA-512");
            // Encrypt(data, RSAEncryptionPadding.OaepSHA512)
            case 27 -> assertOperation(node, Encrypt.class, "OAEP", "SHA-512");
            // RSA.Create(ConfiguredKeySize) with a const field
            case 28 -> assertKeySize(node, 3072);
            // RSA.Create(parameters): an RSAParameters value is not a key size
            case 29 -> assertKeySize(node, null);
            // Encrypt(data, padding) where padding comes from a helper: no padding may be reported
            case 30 -> assertOperation(node, Encrypt.class, null, null);
            // SignData(data, algorithm, Pkcs1) with disagreeing callers: padding yes, digest no
            case 31 -> assertOperation(node, Sign.class, "PKCS1", null);
            default -> throw new IllegalStateException("Unexpected findingId: " + findingId);
        }
    }

    /** A {@code null} expectation asserts absence, not a default. */
    private static void assertKeySize(@Nonnull INode node, @Nullable Integer expectedBits) {
        assertThat(node.asString()).isEqualTo(expectedBits == null ? "RSA" : "RSA-" + expectedBits);
        assertChild(node, KeyLength.class, expectedBits);
    }

    /**
     * Asserts that the RSA node carries the given operation and that the operation carries, or
     * deliberately lacks, a padding and a digest. For an OAEP padding the digest is asserted on the
     * padding node, where .NET puts it; for a signing operation it is asserted on the operation.
     */
    private static void assertOperation(
            @Nonnull INode node,
            @Nonnull Class<? extends INode> operation,
            @Nullable String expectedPadding,
            @Nullable String expectedDigest) {
        INode operationNode = node.getChildren().get(operation);
        assertThat(operationNode)
                .as("expected an %s operation", operation.getSimpleName())
                .isNotNull();
        assertChild(operationNode, Padding.class, expectedPadding);
        if ("OAEP".equals(expectedPadding)) {
            assertChild(
                    operationNode.getChildren().get(Padding.class),
                    MessageDigest.class,
                    expectedDigest);
        } else {
            assertChild(operationNode, MessageDigest.class, expectedDigest);
        }
    }
}
