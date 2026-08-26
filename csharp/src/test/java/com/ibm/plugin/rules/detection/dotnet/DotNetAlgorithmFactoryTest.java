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
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.CipherAction;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.MacContext;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.functionality.Decrypt;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * Test for the generic, string-based {@code Create(string)} factory methods declared directly on
 * the abstract base classes of {@code System.Security.Cryptography} ({@code
 * DotNetAlgorithmFactory.java}): {@code SymmetricAlgorithm.Create(string)}, {@code
 * HashAlgorithm.Create(string)}, {@code KeyedHashAlgorithm.Create(string)}, {@code
 * HMAC.Create(string)}, {@code AsymmetricAlgorithm.Create(string)}.
 *
 * <p>Finding mapping (one finding per test method in {@code DotNetAlgorithmFactoryTestFile.cs}):
 *
 * <pre>
 *  0 TestSymmetricAlgorithmCreateAes        → CipherContext, Algorithm "AES"
 *  1 TestSymmetricAlgorithmCreateRc2        → CipherContext, Algorithm "RC2"
 *  2 TestSymmetricAlgorithmCreateTripleDes  → CipherContext, Algorithm "3DES"
 *  3 TestSymmetricAlgorithmCreateDes        → CipherContext, Algorithm "DES"
 *  4 TestSymmetricAlgorithmCreateAesWithEncryptorAndDecryptor → CipherContext, Algorithm "AES",
 *      plus two child findings (CipherAction "ENCRYPT" from CreateEncryptor(key, iv) and
 *      CipherAction "DECRYPT" from CreateDecryptor(key, iv)) — exercises the depending rules now
 *      attached to SYMMETRIC_ALGORITHM_CREATE.
 *  5 TestHashAlgorithmCreateSha256          → DigestContext, Algorithm "SHA256"
 *  6 TestHashAlgorithmCreateShaHyphenated   → DigestContext, Algorithm "SHA-512"
 *  7 TestHashAlgorithmCreateMd5             → DigestContext, Algorithm "MD5"
 *  8 TestHashAlgorithmCreateShaBare         → DigestContext, Algorithm "SHA"
 *  9 TestKeyedHashAlgorithmCreateHmacSha256 → MacContext, Algorithm "HMACSHA256"
 * 10 TestKeyedHashAlgorithmCreateMacTripleDes → MacContext, Algorithm "MACTripleDES"
 * 11 TestHmacCreateHmacSha1                 → MacContext, Algorithm "HMACSHA1"
 * 12 TestHmacCreateFullyQualified           → MacContext, Algorithm
 *      "System.Security.Cryptography.HMACSHA256"
 * 13 TestAsymmetricAlgorithmCreateRsa       → KeyContext, Algorithm "RSA"
 * 14 TestAsymmetricAlgorithmCreateDsa       → KeyContext, Algorithm "DSA"
 * 15 TestAsymmetricAlgorithmCreateEcdsa     → KeyContext, Algorithm "ECDsa"
 * 16 TestAsymmetricAlgorithmCreateEcdh      → KeyContext, Algorithm "ECDH"
 * </pre>
 */
class DotNetAlgorithmFactoryTest extends TestBase {

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/dotnet/DotNetAlgorithmFactoryTestFile.cs", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {

        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        IValue<CSharpTree> value = detectionStore.getDetectionValues().get(0);
        assertThat(value).isInstanceOf(Algorithm.class);

        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);

        switch (findingId) {
            case 0 -> {
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(CipherContext.class);
                assertThat(value.asString()).isEqualTo("AES");
                assertThat(node.asString()).isEqualTo("AES");
            }
            case 1 -> {
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(CipherContext.class);
                assertThat(value.asString()).isEqualTo("RC2");
                assertThat(node.asString()).isEqualTo("RC2");
            }
            case 2 -> {
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(CipherContext.class);
                assertThat(value.asString()).isEqualTo("3DES");
                assertThat(node.asString()).isEqualTo("DESede");
            }
            case 3 -> {
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(CipherContext.class);
                assertThat(value.asString()).isEqualTo("DES");
                assertThat(node.asString()).isEqualTo("DES-56");
            }
            case 4 -> {
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(CipherContext.class);
                assertThat(value.asString()).isEqualTo("AES");
                assertThat(node.asString()).isEqualTo("AES");
                assertThat(node.getKind()).isEqualTo(BlockCipher.class);
                assertThat(node.getChildren().get(Encrypt.class)).isNotNull();
                assertThat(node.getChildren().get(Decrypt.class)).isNotNull();

                // detectionStore.getChildren() has one entry per depending rule attached to
                // SYMMETRIC_ALGORITHM_CREATE (28: 4 property setters + 24 cipher ops), most of
                // them empty for this call site; only the two that actually matched
                // (CreateEncryptor/CreateDecryptor) carry a detection value.
                List<DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>>
                        populatedChildren =
                                detectionStore.getChildren().stream()
                                        .filter(child -> !child.getDetectionValues().isEmpty())
                                        .toList();
                assertThat(populatedChildren).hasSize(2);
                Set<String> childActions =
                        populatedChildren.stream()
                                .map(
                                        child -> {
                                            assertThat(child.getDetectionValues()).hasSize(1);
                                            IValue<CSharpTree> childValue =
                                                    child.getDetectionValues().get(0);
                                            assertThat(childValue).isInstanceOf(CipherAction.class);
                                            return childValue.asString();
                                        })
                                .collect(Collectors.toSet());
                assertThat(childActions).containsExactlyInAnyOrder("ENCRYPT", "DECRYPT");
            }
            case 5 -> {
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(DigestContext.class);
                assertThat(value.asString()).isEqualTo("SHA256");
                assertThat(node.asString()).isEqualTo("SHA-256");
            }
            case 6 -> {
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(DigestContext.class);
                assertThat(value.asString()).isEqualTo("SHA-512");
                assertThat(node.asString()).isEqualTo("SHA-512");
            }
            case 7 -> {
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(DigestContext.class);
                assertThat(value.asString()).isEqualTo("MD5");
                assertThat(node.asString()).isEqualTo("MD5");
            }
            case 8 -> {
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(DigestContext.class);
                assertThat(value.asString()).isEqualTo("SHA");
                assertThat(node.asString()).isEqualTo("SHA-1");
            }
            case 9 -> {
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(MacContext.class);
                assertThat(value.asString()).isEqualTo("HMACSHA256");
                assertThat(node.asString()).isEqualTo("HMAC-SHA-256");
            }
            case 10 -> {
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(MacContext.class);
                assertThat(value.asString()).isEqualTo("MACTripleDES");
                assertThat(node.asString()).isEqualTo("DESede");
            }
            case 11 -> {
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(MacContext.class);
                assertThat(value.asString()).isEqualTo("HMACSHA1");
                assertThat(node.asString()).isEqualTo("HMAC-SHA-1");
            }
            case 12 -> {
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(MacContext.class);
                assertThat(value.asString()).isEqualTo("System.Security.Cryptography.HMACSHA256");
                assertThat(node.asString()).isEqualTo("HMAC-SHA-256");
            }
            case 13 -> {
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(KeyContext.class);
                assertThat(value.asString()).isEqualTo("RSA");
                assertThat(node.asString()).isEqualTo("RSA");
            }
            case 14 -> {
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(KeyContext.class);
                assertThat(value.asString()).isEqualTo("DSA");
                assertThat(node.asString()).isEqualTo("DSA");
            }
            case 15 -> {
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(KeyContext.class);
                assertThat(value.asString()).isEqualTo("ECDsa");
                assertThat(node.asString()).isEqualTo("ECDSA");
            }
            case 16 -> {
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(KeyContext.class);
                assertThat(value.asString()).isEqualTo("ECDH");
                assertThat(node.asString()).isEqualTo("ECDH");
            }
            default -> throw new IllegalStateException("Unexpected findingId: " + findingId);
        }
    }
}
