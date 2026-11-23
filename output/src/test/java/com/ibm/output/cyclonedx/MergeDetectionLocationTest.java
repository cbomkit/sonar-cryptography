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

import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.functionality.Decrypt;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.mapper.model.functionality.Tag;
import com.ibm.mapper.model.padding.ISO9796Padding;
import com.ibm.mapper.model.padding.PKCS1;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;
import java.util.function.Supplier;
import javax.annotation.Nonnull;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.component.crypto.AlgorithmProperties;
import org.cyclonedx.model.component.crypto.CryptoProperties;
import org.cyclonedx.model.component.crypto.enums.AssetType;
import org.cyclonedx.model.component.crypto.enums.CryptoFunction;
import org.cyclonedx.model.component.crypto.enums.Padding;
import org.cyclonedx.model.component.evidence.Occurrence;
import org.junit.jupiter.api.Test;

class MergeDetectionLocationTest extends TestBase {

    @Test
    void differentContexts() {
        this.assertsNodes(
                () -> {
                    DetectionLocation detectionLocation2 =
                            new DetectionLocation(
                                    "test2.java", 2, 2, Collections.emptyList(), () -> "SSL");
                    return List.of(new RSA(detectionLocation), new RSA(detectionLocation2));
                },
                bom -> {
                    assertThat(bom.getComponents()).hasSize(1);
                    Component component = bom.getComponents().get(0);
                    assertThat(component.getName()).isEqualTo("RSA");

                    CryptoProperties cryptoProperties = component.getCryptoProperties();
                    assertThat(cryptoProperties.getAssetType()).isEqualTo(AssetType.ALGORITHM);

                    assertThat(component.getEvidence().getOccurrences()).hasSize(2);
                    assertThat(
                                    component.getEvidence().getOccurrences().stream()
                                            .map(Occurrence::getLocation))
                            .contains("test.java", "test2.java");
                });
    }

    @Test
    void sameContexts() {
        this.assertsNodes(
                () -> List.of(new RSA(detectionLocation), new RSA(detectionLocation)),
                bom -> {
                    assertThat(bom.getComponents()).hasSize(1);
                    Component component = bom.getComponents().get(0);
                    assertThat(component.getName()).isEqualTo("RSA");

                    CryptoProperties cryptoProperties = component.getCryptoProperties();
                    assertThat(cryptoProperties.getAssetType()).isEqualTo(AssetType.ALGORITHM);

                    assertThat(component.getEvidence().getOccurrences()).hasSize(1);
                    assertThat(component.getEvidence().getOccurrences().get(0).getLocation())
                            .isEqualTo("test.java");
                });
    }

    /**
     * A cipher created twice from the same string, once to decrypt and once to encrypt, is one
     * component, because the direction is not part of the name. Both directions must survive.
     */
    @Test
    void keepsBothDirectionsOfACipherUsedTwice() {
        this.assertsNodes(
                () -> List.of(aesWith(Decrypt::new), aesWith(Encrypt::new)),
                bom -> {
                    assertThat(bom.getComponents()).hasSize(1);
                    final Component component = bom.getComponents().get(0);
                    assertThat(component.getName()).isEqualTo("AES");
                    assertThat(component.getEvidence().getOccurrences()).hasSize(2);
                    assertThat(algorithmProperties(component).getCryptoFunctions())
                            .containsExactlyInAnyOrder(
                                    CryptoFunction.DECRYPT, CryptoFunction.ENCRYPT);
                });
    }

    /**
     * {@code RSA.asString()} names only an OAEP padding, so an RSA with PKCS#1 and one without a
     * padding are one component. The padding is stated by only one of them, so it is cleared, in
     * either order.
     */
    @Test
    void clearsPaddingStatedByOnlyOneCallSite() {
        for (List<Function<DetectionLocation, INode>> order :
                List.of(
                        List.<Function<DetectionLocation, INode>>of(this::rsa, this::rsaPkcs1),
                        List.<Function<DetectionLocation, INode>>of(this::rsaPkcs1, this::rsa))) {
            this.assertsNodes(
                    () -> build(order),
                    bom -> {
                        assertThat(bom.getComponents()).hasSize(1);
                        final Component component = bom.getComponents().get(0);
                        assertThat(component.getName()).isEqualTo("RSA");
                        assertThat(component.getEvidence().getOccurrences()).hasSize(2);
                        assertThat(algorithmProperties(component).getPadding())
                                .as("a padding stated by only one of the two call sites")
                                .isNull();
                        assertThat(component.getCryptoProperties().getOid())
                                .as("the OID both state")
                                .isEqualTo("1.2.840.113549.1.1.1");
                    });
        }
    }

    @Test
    void clearsPaddingTheCallSitesDisagreeOn() {
        for (List<Function<DetectionLocation, INode>> order :
                List.of(
                        List.<Function<DetectionLocation, INode>>of(
                                this::rsaPkcs1, this::rsaIso9796),
                        List.<Function<DetectionLocation, INode>>of(
                                this::rsaIso9796, this::rsaPkcs1))) {
            this.assertsNodes(
                    () -> build(order),
                    bom -> {
                        assertThat(bom.getComponents()).hasSize(1);
                        assertThat(algorithmProperties(bom.getComponents().get(0)).getPadding())
                                .isNull();
                    });
        }
    }

    @Test
    void keepsPaddingAllCallSitesAgreeOn() {
        this.assertsNodes(
                () -> build(List.of(this::rsaPkcs1, this::rsaPkcs1, this::rsaPkcs1)),
                bom -> {
                    assertThat(bom.getComponents()).hasSize(1);
                    final Component component = bom.getComponents().get(0);
                    assertThat(component.getEvidence().getOccurrences()).hasSize(3);
                    assertThat(algorithmProperties(component).getPadding())
                            .isEqualTo(Padding.PKCS1V15);
                });
    }

    /**
     * Merging is pairwise, so a padding cleared by the second detection must stay cleared when a
     * third one states it again, whatever the order.
     */
    @Test
    void clearedPaddingStaysClearedAcrossThreeCallSites() {
        final Function<DetectionLocation, INode> pkcs1 = this::rsaPkcs1;
        final Function<DetectionLocation, INode> none = this::rsa;
        for (List<Function<DetectionLocation, INode>> order :
                List.of(
                        List.of(pkcs1, none, pkcs1),
                        List.of(none, pkcs1, pkcs1),
                        List.of(pkcs1, pkcs1, none))) {
            this.assertsNodes(
                    () -> build(order),
                    bom -> {
                        assertThat(bom.getComponents()).hasSize(1);
                        final Component component = bom.getComponents().get(0);
                        assertThat(component.getEvidence().getOccurrences()).hasSize(3);
                        assertThat(algorithmProperties(component).getPadding()).isNull();
                    });
        }
    }

    /** Three call sites with overlapping function sets give the union, in any arrival order. */
    @Test
    void unionsFunctionsAcrossThreeCallSitesRegardlessOfOrder() {
        final List<Supplier<List<INode>>> orders =
                List.of(
                        () ->
                                List.of(
                                        aesWith(Encrypt::new, Decrypt::new),
                                        aesWith(KeyGeneration::new),
                                        aesWith(Decrypt::new, Tag::new)),
                        () ->
                                List.of(
                                        aesWith(Decrypt::new, Tag::new),
                                        aesWith(Encrypt::new, Decrypt::new),
                                        aesWith(KeyGeneration::new)),
                        () ->
                                List.of(
                                        aesWith(KeyGeneration::new),
                                        aesWith(Decrypt::new, Tag::new),
                                        aesWith(Encrypt::new, Decrypt::new)));

        for (Supplier<List<INode>> order : orders) {
            final List<INode> nodes = order.get();
            this.assertsNodes(
                    () -> nodes,
                    bom -> {
                        assertThat(bom.getComponents()).hasSize(1);
                        final Component component = bom.getComponents().get(0);
                        assertThat(component.getEvidence().getOccurrences()).hasSize(3);
                        assertThat(algorithmProperties(component).getCryptoFunctions())
                                .containsExactlyInAnyOrder(
                                        CryptoFunction.ENCRYPT,
                                        CryptoFunction.DECRYPT,
                                        CryptoFunction.KEYGEN,
                                        CryptoFunction.TAG);
                    });
        }
    }

    @Nonnull
    private static AlgorithmProperties algorithmProperties(@Nonnull Component component) {
        return component.getCryptoProperties().getAlgorithmProperties();
    }

    /** One node per factory, each at its own location. */
    @Nonnull
    private List<INode> build(@Nonnull List<Function<DetectionLocation, INode>> factories) {
        return factories.stream().map(factory -> factory.apply(nextLocation())).toList();
    }

    @Nonnull
    private INode rsa(@Nonnull DetectionLocation location) {
        return new RSA(location);
    }

    @Nonnull
    private INode rsaPkcs1(@Nonnull DetectionLocation location) {
        final INode rsa = new RSA(location);
        rsa.put(new PKCS1(location));
        return rsa;
    }

    @Nonnull
    private INode rsaIso9796(@Nonnull DetectionLocation location) {
        final INode rsa = new RSA(location);
        rsa.put(new ISO9796Padding(location));
        return rsa;
    }

    /** An AES at its own location, carrying the given functionalities and nothing else. */
    @SafeVarargs
    @Nonnull
    private INode aesWith(@Nonnull Function<DetectionLocation, INode>... functionalities) {
        final DetectionLocation location = nextLocation();
        final INode aes = new AES(location);
        for (Function<DetectionLocation, INode> functionality : functionalities) {
            aes.put(functionality.apply(location));
        }
        return aes;
    }

    @Nonnull
    private DetectionLocation nextLocation() {
        final int line = nextLine++;
        return new DetectionLocation("test" + line + ".java", line, line, List.of(), bundle);
    }

    private int nextLine = 10;
}
