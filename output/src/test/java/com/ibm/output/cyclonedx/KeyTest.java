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
package com.ibm.output.cyclonedx;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.mapper.model.AuthenticatedEncryption;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.PublicKey;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.SecretKey;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.functionality.Decrypt;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.mapper.model.mode.GCM;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.component.crypto.AlgorithmProperties;
import org.cyclonedx.model.component.crypto.CryptoProperties;
import org.cyclonedx.model.component.crypto.RelatedCryptoMaterialProperties;
import org.cyclonedx.model.component.crypto.enums.AssetType;
import org.cyclonedx.model.component.crypto.enums.CryptoFunction;
import org.cyclonedx.model.component.crypto.enums.Primitive;
import org.cyclonedx.model.component.crypto.enums.RelatedCryptoMaterialType;
import org.junit.jupiter.api.Test;

class KeyTest extends TestBase {

    @Test
    void base() {
        this.assertsNode(
                () -> new PublicKey((PublicKeyEncryption) new RSA(detectionLocation)),
                bom -> {
                    assertThat(bom.getComponents()).hasSize(2);
                    for (Component component : bom.getComponents()) {
                        asserts(component.getEvidence());
                        assertThat(component.getCryptoProperties()).isNotNull();
                        final CryptoProperties cryptoProperties = component.getCryptoProperties();

                        if (cryptoProperties.getAssetType().equals(AssetType.ALGORITHM)) {
                            assertThat(component.getName()).isEqualTo("RSA");
                            assertThat(cryptoProperties.getAlgorithmProperties()).isNotNull();
                            final AlgorithmProperties algorithmProperties =
                                    cryptoProperties.getAlgorithmProperties();
                            assertThat(algorithmProperties.getPrimitive()).isEqualTo(Primitive.PKE);
                            assertThat(cryptoProperties.getOid()).isEqualTo("1.2.840.113549.1.1.1");
                        } else if (cryptoProperties
                                .getAssetType()
                                .equals(AssetType.RELATED_CRYPTO_MATERIAL)) {
                            assertThat(cryptoProperties.getRelatedCryptoMaterialProperties())
                                    .isNotNull();
                            final RelatedCryptoMaterialProperties relatedCryptoMaterialProperties =
                                    cryptoProperties.getRelatedCryptoMaterialProperties();
                            assertThat(relatedCryptoMaterialProperties.getType())
                                    .isEqualTo(RelatedCryptoMaterialType.PUBLIC_KEY);
                        } else {
                            throw new AssertionError();
                        }
                    }
                });
    }

    @Test
    void secretKey() {
        this.assertsNode(
                () -> {
                    final AES aes =
                            new AES(
                                    AuthenticatedEncryption.class,
                                    new AES(128, new GCM(detectionLocation), detectionLocation));
                    aes.put(new Oid("2.16.840.1.101.3.4.1.6", detectionLocation));
                    final SecretKey secretKey = new SecretKey(aes);
                    secretKey.put(new KeyGeneration(detectionLocation));
                    secretKey.put(new Encrypt(detectionLocation));
                    secretKey.put(new Decrypt(detectionLocation));
                    return secretKey;
                },
                bom -> {
                    assertThat(bom.getComponents()).hasSize(2);
                    for (Component component : bom.getComponents()) {
                        asserts(component.getEvidence());
                        assertThat(component.getCryptoProperties()).isNotNull();
                        final CryptoProperties cryptoProperties = component.getCryptoProperties();

                        if (cryptoProperties.getAssetType().equals(AssetType.ALGORITHM)) {
                            assertThat(component.getName()).isEqualTo("AES-128-GCM");
                            assertThat(cryptoProperties.getAlgorithmProperties()).isNotNull();
                            final AlgorithmProperties algorithmProperties =
                                    cryptoProperties.getAlgorithmProperties();
                            assertThat(algorithmProperties.getPrimitive()).isEqualTo(Primitive.AE);
                            assertThat(algorithmProperties.getParameterSetIdentifier())
                                    .isEqualTo("128");
                            assertThat(algorithmProperties.getCryptoFunctions())
                                    .contains(
                                            CryptoFunction.DECRYPT,
                                            CryptoFunction.ENCRYPT,
                                            CryptoFunction.KEYGEN);
                            assertThat(cryptoProperties.getOid())
                                    .isEqualTo("2.16.840.1.101.3.4.1.6");
                        } else if (cryptoProperties
                                .getAssetType()
                                .equals(AssetType.RELATED_CRYPTO_MATERIAL)) {
                            assertThat(cryptoProperties.getRelatedCryptoMaterialProperties())
                                    .isNotNull();
                            final RelatedCryptoMaterialProperties relatedCryptoMaterialProperties =
                                    cryptoProperties.getRelatedCryptoMaterialProperties();
                            assertThat(relatedCryptoMaterialProperties.getType())
                                    .isEqualTo(RelatedCryptoMaterialType.SECRET_KEY);
                        } else {
                            throw new AssertionError();
                        }
                    }
                });
    }

    @Test
    void updateKeySizeInAlgorithm() {
        this.assertsNode(
                () -> {
                    final RSA rsa = new RSA(2048, detectionLocation);
                    final PublicKey publicKey = new PublicKey((PublicKeyEncryption) rsa);
                    publicKey.put(new KeyLength(4096, detectionLocation));
                    return publicKey;
                },
                bom -> {
                    assertThat(bom.getComponents()).hasSize(2);
                    for (Component component : bom.getComponents()) {
                        asserts(component.getEvidence());
                        assertThat(component.getCryptoProperties()).isNotNull();
                        final CryptoProperties cryptoProperties = component.getCryptoProperties();

                        if (cryptoProperties.getAssetType().equals(AssetType.ALGORITHM)) {
                            assertThat(component.getName()).isEqualTo("RSA-4096");
                            assertThat(cryptoProperties.getAlgorithmProperties()).isNotNull();
                            final AlgorithmProperties algorithmProperties =
                                    cryptoProperties.getAlgorithmProperties();
                            assertThat(algorithmProperties.getPrimitive()).isEqualTo(Primitive.PKE);
                            assertThat(algorithmProperties.getParameterSetIdentifier())
                                    .isEqualTo("4096");
                            assertThat(cryptoProperties.getOid()).isEqualTo("1.2.840.113549.1.1.1");
                        } else if (cryptoProperties
                                .getAssetType()
                                .equals(AssetType.RELATED_CRYPTO_MATERIAL)) {
                            assertThat(cryptoProperties.getRelatedCryptoMaterialProperties())
                                    .isNotNull();
                            final RelatedCryptoMaterialProperties relatedCryptoMaterialProperties =
                                    cryptoProperties.getRelatedCryptoMaterialProperties();
                            assertThat(relatedCryptoMaterialProperties.getType())
                                    .isEqualTo(RelatedCryptoMaterialType.PUBLIC_KEY);
                        } else {
                            throw new AssertionError();
                        }
                    }
                });
    }
}
