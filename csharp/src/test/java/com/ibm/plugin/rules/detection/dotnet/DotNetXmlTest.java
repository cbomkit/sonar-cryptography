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
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.junit.jupiter.api.Test;

/**
 * Covers {@code System.Security.Cryptography.Xml}: the digest, signature and encryption
 * identifiers, as constants and as URI literals, including the chained {@code
 * signedXml.SignedInfo.SignatureMethod = …}.
 *
 * <p>An unknown URI gives a finding with no node. An unknown value gives no finding, so a finding
 * with id 12 fails the test.
 */
class DotNetXmlTest extends TestBase {

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/dotnet/DotNetXmlTestFile.cs", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        if (findingId == 10) {
            // a URI of another kind: no node
            assertThat(nodes).isEmpty();
            return;
        }
        assertThat(nodes).hasSize(1);
        final INode node = nodes.get(0);

        switch (findingId) {
            // reference.DigestMethod: constant, literal, weak digest, initializer
            case 0 -> assertDigest(node, "SHA-256");
            case 1 -> assertDigest(node, "SHA-512");
            case 2 -> assertDigest(node, "SHA-1");
            case 3 -> assertDigest(node, "SHA-384");
            // RSA signature: the digest and the PKCS#1 padding
            case 4 -> assertSignature(node, "RSA-PKCS1-1.5-SHA-256", "SHA-256", "PKCS1");
            // ECDSA signature: a digest, and no padding may be invented
            case 5 -> assertSignature(node, "ECDSA-SHA-384", "SHA-384", null);
            // an HMAC identifier is a MAC, not a signature
            case 6 -> {
                assertThat(node.getKind()).isEqualTo(Mac.class);
                assertThat(node.asString()).isEqualTo("HMAC-SHA-1");
            }
            // new EncryptionMethod(EncryptedXml.XmlEncAES256Url)
            case 7 -> {
                assertThat(node.getKind()).isEqualTo(BlockCipher.class);
                assertThat(node.asString()).isEqualTo("AES-256-CBC");
            }
            // rsa-oaep-mgf1p is OAEP with SHA-1, fixed by the identifier
            case 8 -> {
                assertThat(node.getKind()).isEqualTo(PublicKeyEncryption.class);
                assertThat(node.asString()).isEqualTo("RSA-OAEP");
                assertChild(node.getChildren().get(Padding.class), MessageDigest.class, "SHA-1");
            }
            // encryptionMethod.KeyAlgorithm = EncryptedXml.XmlEncTripleDESUrl: no key length stated
            case 9 -> {
                assertThat(node.getKind()).isEqualTo(BlockCipher.class);
                assertThat(node.asString()).isEqualTo("DESede-CBC");
                assertChild(node, Mode.class, "CBC");
            }
            // signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA256Url
            case 11 -> assertSignature(node, "RSA-PKCS1-1.5-SHA-256", "SHA-256", "PKCS1");
            default -> throw new IllegalStateException("Unexpected findingId: " + findingId);
        }
    }

    private static void assertDigest(@Nonnull INode node, @Nonnull String expected) {
        assertThat(node.getKind()).isEqualTo(MessageDigest.class);
        assertThat(node.asString()).isEqualTo(expected);
    }

    /**
     * A {@code SignatureMethod} URI names the algorithm as plainly as the digest, so the node is
     * rooted at the algorithm with the digest, the padding and the {@code Sign} beneath it. Rooted
     * at a {@code Sign} instead, as it was, the algorithm and the padding never reached the CBOM.
     */
    private static void assertSignature(
            @Nonnull INode node,
            @Nonnull String expectedAlgorithm,
            @Nonnull String expectedDigest,
            @Nullable String expectedPadding) {
        assertThat(node.asString()).isEqualTo(expectedAlgorithm);
        assertThat(node.hasChildOfType(Sign.class)).isPresent();
        assertChild(node, MessageDigest.class, expectedDigest);
        assertChild(node, Padding.class, expectedPadding);
    }
}
