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

import com.ibm.mapper.model.CipherSuite;
import com.ibm.mapper.model.Identifier;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.Version;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.DH;
import com.ibm.mapper.model.algorithms.DSA;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.collections.AssetCollection;
import com.ibm.mapper.model.collections.CipherSuiteCollection;
import com.ibm.mapper.model.collections.IdentifierCollection;
import com.ibm.mapper.model.mode.CBC;
import com.ibm.mapper.model.protocol.IPSec;
import com.ibm.mapper.model.protocol.TLS;
import java.util.List;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.component.crypto.AlgorithmProperties;
import org.cyclonedx.model.component.crypto.CryptoProperties;
import org.cyclonedx.model.component.crypto.ProtocolProperties;
import org.cyclonedx.model.component.crypto.enums.AssetType;
import org.cyclonedx.model.component.crypto.enums.Mode;
import org.cyclonedx.model.component.crypto.enums.Primitive;
import org.cyclonedx.model.component.crypto.enums.ProtocolType;
import org.junit.jupiter.api.Test;

class ProtocolTest extends TestBase {

    @Test
    void base() {
        this.assertsNode(
                () -> new TLS(new Version("1.3", detectionLocation)),
                bom -> {
                    assertThat(bom.getComponents()).hasSize(1);
                    assertThat(bom.getComponents())
                            .anyMatch(
                                    component -> {
                                        asserts(component.getEvidence());
                                        CryptoProperties c = component.getCryptoProperties();
                                        return component.getName().equals("TLSv1.3")
                                                && c.getProtocolProperties()
                                                        .getType()
                                                        .equals(ProtocolType.TLS)
                                                && c.getProtocolProperties()
                                                        .getVersion()
                                                        .equals("1.3");
                                    });
                });
    }

    @Test
    void cipherSuite() {
        this.assertsNode(
                () -> {
                    final CipherSuite cipherSuite =
                            new CipherSuite(
                                    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", detectionLocation);
                    final DH dh = new DH(KeyAgreement.class, detectionLocation);
                    final AES aes = new AES(256, new CBC(detectionLocation), detectionLocation);
                    final DSA dsa = new DSA(new SHA2(256, detectionLocation));
                    dsa.put(new Oid("2.16.840.1.101.3.4.3.2", detectionLocation));
                    final AssetCollection assetCollection =
                            new AssetCollection(List.of(dh, aes, dsa));
                    final IdentifierCollection identifierCollection =
                            new IdentifierCollection(
                                    List.of(
                                            new Identifier("0x00", detectionLocation),
                                            new Identifier("0x6A", detectionLocation)));
                    cipherSuite.put(assetCollection);
                    cipherSuite.put(identifierCollection);
                    return cipherSuite;
                },
                bom -> {
                    assertThat(bom.getComponents()).hasSize(5);
                    assertThat(bom.getComponents().stream().map(Component::getName))
                            .contains("SHA256withDSA", "SHA256", "AES256-CBC", "TLS", "DH");

                    for (Component component : bom.getComponents()) {
                        asserts(component.getEvidence());
                        assertThat(component.getCryptoProperties()).isNotNull();
                        final CryptoProperties cryptoProperties = component.getCryptoProperties();

                        if (cryptoProperties.getAssetType().equals(AssetType.ALGORITHM)) {
                            assertThat(cryptoProperties.getAlgorithmProperties()).isNotNull();
                            final AlgorithmProperties algorithmProperties =
                                    cryptoProperties.getAlgorithmProperties();
                            if (algorithmProperties.getPrimitive().equals(Primitive.SIGNATURE)) {
                                assertThat(component.getName()).isEqualTo("SHA256withDSA");
                                assertThat(cryptoProperties.getOid())
                                        .isEqualTo("2.16.840.1.101.3.4.3.2");
                            } else if (algorithmProperties.getPrimitive().equals(Primitive.HASH)) {
                                assertThat(component.getName()).isEqualTo("SHA256");
                                assertThat(algorithmProperties.getParameterSetIdentifier())
                                        .isEqualTo("256");
                            } else if (algorithmProperties
                                    .getPrimitive()
                                    .equals(Primitive.KEY_AGREE)) {
                                assertThat(component.getName()).isEqualTo("DH");
                                assertThat(cryptoProperties.getOid())
                                        .isEqualTo("1.2.840.113549.1.3.1");
                            } else if (algorithmProperties
                                    .getPrimitive()
                                    .equals(Primitive.BLOCK_CIPHER)) {
                                assertThat(component.getName()).isEqualTo("AES256-CBC");
                                assertThat(algorithmProperties.getMode()).isEqualTo(Mode.CBC);
                                assertThat(algorithmProperties.getParameterSetIdentifier())
                                        .isEqualTo("256");
                            } else {
                                throw new AssertionError();
                            }
                        } else if (cryptoProperties.getAssetType().equals(AssetType.PROTOCOL)) {
                            assertThat(cryptoProperties.getProtocolProperties()).isNotNull();
                            final ProtocolProperties protocolProperties =
                                    cryptoProperties.getProtocolProperties();
                            assertThat(protocolProperties.getType()).isEqualTo(ProtocolType.TLS);
                            assertThat(protocolProperties.getVersion()).isNull();
                            assertThat(protocolProperties.getCipherSuites()).isNotNull();
                            assertThat(protocolProperties.getCipherSuites()).hasSize(1);

                            final org.cyclonedx.model.component.crypto.CipherSuite cipherSuite =
                                    protocolProperties.getCipherSuites().get(0);
                            assertThat(cipherSuite.getName())
                                    .isEqualTo("TLS_DHE_DSS_WITH_AES_256_CBC_SHA256");

                            assertThat(cipherSuite.getAlgorithms()).hasSize(3);
                            assertThat(cipherSuite.getIdentifiers()).contains("0x00", "0x6A");
                        }
                    }
                });
    }

    @Test
    void protocolWithCipherSuite() {
        this.assertsNode(
                () -> {
                    final TLS tls = new TLS(new Version("1.3", detectionLocation));

                    final CipherSuite cipherSuite =
                            new CipherSuite(
                                    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", detectionLocation);
                    final DH dh = new DH(KeyAgreement.class, detectionLocation);
                    final AES aes = new AES(256, new CBC(detectionLocation), detectionLocation);
                    final DSA dsa = new DSA(new SHA2(256, detectionLocation));
                    dsa.put(new Oid("2.16.840.1.101.3.4.3.2", detectionLocation));
                    final AssetCollection assetCollection =
                            new AssetCollection(List.of(dh, aes, dsa));
                    final IdentifierCollection identifierCollection =
                            new IdentifierCollection(
                                    List.of(
                                            new Identifier("0x00", detectionLocation),
                                            new Identifier("0x6A", detectionLocation)));
                    cipherSuite.put(assetCollection);
                    cipherSuite.put(identifierCollection);

                    tls.put(new CipherSuiteCollection(List.of(cipherSuite)));
                    return tls;
                },
                bom -> {
                    assertThat(bom.getComponents()).hasSize(5);
                    assertThat(bom.getComponents().stream().map(Component::getName))
                            .contains("SHA256withDSA", "SHA256", "AES256-CBC", "TLSv1.3", "DH");

                    for (Component component : bom.getComponents()) {
                        asserts(component.getEvidence());
                        assertThat(component.getCryptoProperties()).isNotNull();
                        final CryptoProperties cryptoProperties = component.getCryptoProperties();

                        if (cryptoProperties.getAssetType().equals(AssetType.ALGORITHM)) {
                            assertThat(cryptoProperties.getAlgorithmProperties()).isNotNull();
                            final AlgorithmProperties algorithmProperties =
                                    cryptoProperties.getAlgorithmProperties();
                            if (algorithmProperties.getPrimitive().equals(Primitive.SIGNATURE)) {
                                assertThat(component.getName()).isEqualTo("SHA256withDSA");
                                assertThat(cryptoProperties.getOid())
                                        .isEqualTo("2.16.840.1.101.3.4.3.2");
                            } else if (algorithmProperties.getPrimitive().equals(Primitive.HASH)) {
                                assertThat(component.getName()).isEqualTo("SHA256");
                                assertThat(algorithmProperties.getParameterSetIdentifier())
                                        .isEqualTo("256");
                            } else if (algorithmProperties
                                    .getPrimitive()
                                    .equals(Primitive.KEY_AGREE)) {
                                assertThat(component.getName()).isEqualTo("DH");
                                assertThat(cryptoProperties.getOid())
                                        .isEqualTo("1.2.840.113549.1.3.1");
                            } else if (algorithmProperties
                                    .getPrimitive()
                                    .equals(Primitive.BLOCK_CIPHER)) {
                                assertThat(component.getName()).isEqualTo("AES256-CBC");
                                assertThat(algorithmProperties.getMode()).isEqualTo(Mode.CBC);
                                assertThat(algorithmProperties.getParameterSetIdentifier())
                                        .isEqualTo("256");
                            } else {
                                throw new AssertionError();
                            }
                        } else if (cryptoProperties.getAssetType().equals(AssetType.PROTOCOL)) {
                            assertThat(cryptoProperties.getProtocolProperties()).isNotNull();
                            final ProtocolProperties protocolProperties =
                                    cryptoProperties.getProtocolProperties();
                            assertThat(protocolProperties.getType()).isEqualTo(ProtocolType.TLS);
                            assertThat(protocolProperties.getVersion()).isEqualTo("1.3");
                            assertThat(protocolProperties.getCipherSuites()).isNotNull();
                            assertThat(protocolProperties.getCipherSuites()).hasSize(1);
                            assertThat(protocolProperties.getCryptoRefArray()).isNotNull();
                            assertThat(protocolProperties.getCryptoRefArray()).hasSize(3);

                            final org.cyclonedx.model.component.crypto.CipherSuite cipherSuite =
                                    protocolProperties.getCipherSuites().get(0);
                            assertThat(cipherSuite.getName())
                                    .isEqualTo("TLS_DHE_DSS_WITH_AES_256_CBC_SHA256");

                            assertThat(cipherSuite.getAlgorithms()).hasSize(3);
                            assertThat(cipherSuite.getIdentifiers()).contains("0x00", "0x6A");
                        }
                    }
                });
    }

    @Test
    void protocolOther() {
        this.assertsNode(
                () -> {
                    final IPSec ipsec = new IPSec(detectionLocation);
                    ipsec.put(new AES(128, new CBC(detectionLocation), detectionLocation));
                    ipsec.put(new RSA(detectionLocation));
                    return ipsec;
                },
                bom -> {
                    assertThat(bom.getComponents()).hasSize(3);
                    assertThat(bom.getComponents().stream().map(Component::getName))
                            .contains("AES128-CBC", "RSA", "IPSec");

                    for (Component component : bom.getComponents()) {
                        asserts(component.getEvidence());
                        assertThat(component.getCryptoProperties()).isNotNull();
                        final CryptoProperties cryptoProperties = component.getCryptoProperties();
                        if (cryptoProperties.getAssetType().equals(AssetType.PROTOCOL)) {
                            assertThat(component.getName()).isEqualTo("IPSec");
                            assertThat(cryptoProperties.getProtocolProperties()).isNotNull();
                            final ProtocolProperties protocolProperties =
                                    cryptoProperties.getProtocolProperties();
                            assertThat(protocolProperties.getType()).isEqualTo(ProtocolType.IPSEC);
                            assertThat(protocolProperties.getVersion()).isNull();
                            assertThat(protocolProperties.getCipherSuites()).isNull();
                            assertThat(protocolProperties.getCryptoRefArray()).isNotNull();
                            assertThat(protocolProperties.getCryptoRefArray()).hasSize(2);
                        }
                    }
                });
    }
}
