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
import com.ibm.mapper.model.padding.PKCS1;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Collections;
import java.util.List;
import javax.annotation.Nonnull;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.component.crypto.CryptoProperties;
import org.cyclonedx.model.component.crypto.enums.AssetType;
import org.cyclonedx.model.component.crypto.enums.CryptoFunction;
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
     * Two call sites that differ only in what they do with the cipher share a component, because
     * the direction is not part of the name. Both directions have to survive that.
     *
     * <p>Reported against nagilum/cryptocsharp, whose {@code Cryptography.cs} creates an RSA on
     * line 171 to decrypt and on line 207 to encrypt: the CBOM listed both lines under one
     * component and claimed it only ever decrypts. The same holds in Java for a {@code
     * Cipher.getInstance("RSA/ECB/OAEPPadding")} used once in each direction.
     */
    @Test
    void keepsBothDirectionsOfACipherUsedTwice() {
        this.assertsNodes(
                () -> {
                    final DetectionLocation second =
                            new DetectionLocation(
                                    "test2.java", 2, 2, Collections.emptyList(), bundle);
                    final INode decrypting = new AES(detectionLocation);
                    decrypting.put(new Decrypt(detectionLocation));
                    final INode encrypting = new AES(second);
                    encrypting.put(new Encrypt(second));
                    return List.of(decrypting, encrypting);
                },
                bom -> {
                    assertThat(bom.getComponents()).hasSize(1);
                    final Component component = bom.getComponents().get(0);
                    assertThat(component.getName()).isEqualTo("AES");
                    assertThat(component.getEvidence().getOccurrences()).hasSize(2);
                    assertThat(
                                    component
                                            .getCryptoProperties()
                                            .getAlgorithmProperties()
                                            .getCryptoFunctions())
                            .containsExactlyInAnyOrder(
                                    CryptoFunction.DECRYPT, CryptoFunction.ENCRYPT);
                });
    }

    /**
     * A single-valued property is never carried over from one call site to another.
     *
     * <p>{@code RSA.asString()} puts only an OAEP padding into the name, so an RSA that states
     * PKCS#1 and an RSA that states no padding at all are one component. Filling the empty field
     * from the other would attach a padding to a line that does not use one — in bitwarden/server
     * exactly that happens, where four of five occurrences named {@code RSA} pass {@code
     * RSASignaturePadding.Pkcs1} and the fifth only retrieves the key. The field stays empty
     * instead, because one component cannot describe both and guessing which to show is worse.
     */
    @Test
    void doesNotCarrySingleValuedPropertiesBetweenCallSites() {
        this.assertsNodes(
                () -> {
                    final DetectionLocation second =
                            new DetectionLocation(
                                    "test2.java", 2, 2, Collections.emptyList(), bundle);
                    final INode withoutPadding = new RSA(detectionLocation);
                    final INode withPadding = new RSA(second);
                    withPadding.put(new PKCS1(second));
                    return List.of(withoutPadding, withPadding);
                },
                bom -> {
                    assertThat(bom.getComponents()).hasSize(1);
                    final Component component = bom.getComponents().get(0);
                    assertThat(component.getName()).isEqualTo("RSA");
                    assertThat(component.getEvidence().getOccurrences()).hasSize(2);
                    assertThat(
                                    component
                                            .getCryptoProperties()
                                            .getAlgorithmProperties()
                                            .getPadding())
                            .as("a padding stated by only one of the two call sites")
                            .isNull();
                });
    }

    /**
     * Three call sites with different, partly overlapping function sets end up with the union of
     * all three, and the result does not depend on the order they arrive in.
     *
     * <p>Merging is pairwise -- every further component is folded into the one already stored -- so
     * the question is whether folding repeatedly can lose something. It cannot: a union is
     * associative, commutative and idempotent, so folding N sets one at a time gives the same
     * answer as taking all N at once, whatever the order. This pins that, because the pairwise
     * shape is what makes it easy to doubt.
     */
    @Test
    void unionsFunctionsAcrossThreeCallSitesRegardlessOfOrder() {
        final List<List<INode>> orders =
                List.of(
                        List.of(aesWith(ENCRYPT, DECRYPT), aesWith(KEYGEN), aesWith(DECRYPT, TAG)),
                        List.of(aesWith(DECRYPT, TAG), aesWith(ENCRYPT, DECRYPT), aesWith(KEYGEN)),
                        List.of(aesWith(KEYGEN), aesWith(DECRYPT, TAG), aesWith(ENCRYPT, DECRYPT)));

        for (List<INode> order : orders) {
            this.assertsNodes(
                    () -> order,
                    bom -> {
                        assertThat(bom.getComponents()).hasSize(1);
                        final Component component = bom.getComponents().get(0);
                        assertThat(component.getEvidence().getOccurrences()).hasSize(3);
                        assertThat(
                                        component
                                                .getCryptoProperties()
                                                .getAlgorithmProperties()
                                                .getCryptoFunctions())
                                .as("the union of all three, in any arrival order")
                                .containsExactlyInAnyOrder(
                                        CryptoFunction.ENCRYPT,
                                        CryptoFunction.DECRYPT,
                                        CryptoFunction.KEYGEN,
                                        CryptoFunction.TAG);
                    });
        }
    }

    private static final String ENCRYPT = "encrypt";
    private static final String DECRYPT = "decrypt";
    private static final String KEYGEN = "keygen";
    private static final String TAG = "tag";

    /** An AES at its own location, carrying the named functionalities and nothing else. */
    @Nonnull
    private INode aesWith(@Nonnull String... functionalities) {
        final DetectionLocation location =
                new DetectionLocation(
                        "test" + nextLine + ".java", nextLine, nextLine, List.of(), bundle);
        nextLine++;
        final INode aes = new AES(location);
        for (String functionality : functionalities) {
            aes.put(
                    switch (functionality) {
                        case ENCRYPT -> new Encrypt(location);
                        case DECRYPT -> new Decrypt(location);
                        case KEYGEN -> new KeyGeneration(location);
                        default -> new Tag(location);
                    });
        }
        return aes;
    }

    private int nextLine = 10;
}
