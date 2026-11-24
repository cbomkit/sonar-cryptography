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
package com.ibm.output.cyclondx;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.component.crypto.AlgorithmProperties;
import org.cyclonedx.model.component.crypto.CryptoProperties;
import org.cyclonedx.model.component.crypto.enums.AssetType;
import org.cyclonedx.model.component.crypto.enums.CryptoFunction;
import org.cyclonedx.model.component.crypto.enums.Padding;
import org.cyclonedx.model.component.crypto.enums.Primitive;
import org.junit.jupiter.api.Test;

/** {@link CBOMOutputFile#mergeCryptoProperties} on components no builder produces today. */
class MergeCryptoPropertiesTest {

    @Test
    void keptWithoutCryptoPropertiesGetsOnlyTheFunctions() {
        final Component kept = new Component();
        final Component incoming = algorithm(CryptoFunction.SIGN);

        CBOMOutputFile.mergeCryptoProperties(kept, incoming);

        final CryptoProperties merged = kept.getCryptoProperties();
        assertThat(merged).isNotSameAs(incoming.getCryptoProperties());
        assertThat(merged.getAssetType()).isEqualTo(AssetType.ALGORITHM);
        assertThat(merged.getOid()).as("stated by only one").isNull();
        assertNoSingleValuedProperty(merged.getAlgorithmProperties());
        assertThat(merged.getAlgorithmProperties().getCryptoFunctions())
                .containsExactly(CryptoFunction.SIGN);
    }

    @Test
    void keptWithoutAlgorithmPropertiesGetsOnlyTheFunctions() {
        final Component kept = new Component();
        final CryptoProperties keptProperties = new CryptoProperties();
        keptProperties.setAssetType(AssetType.ALGORITHM);
        kept.setCryptoProperties(keptProperties);
        final Component incoming = algorithm(CryptoFunction.SIGN);

        CBOMOutputFile.mergeCryptoProperties(kept, incoming);

        final AlgorithmProperties merged = kept.getCryptoProperties().getAlgorithmProperties();
        assertThat(merged).isNotSameAs(incoming.getCryptoProperties().getAlgorithmProperties());
        assertNoSingleValuedProperty(merged);
        assertThat(merged.getCryptoFunctions()).containsExactly(CryptoFunction.SIGN);
    }

    @Test
    void doesNotShareStateWithTheIncomingComponent() {
        final Component kept = algorithm(CryptoFunction.SIGN);
        final Component incoming = algorithm(CryptoFunction.VERIFY);

        CBOMOutputFile.mergeCryptoProperties(kept, incoming);
        incoming.getCryptoProperties().getAlgorithmProperties().getCryptoFunctions().clear();

        final AlgorithmProperties merged = kept.getCryptoProperties().getAlgorithmProperties();
        assertThat(merged.getCryptoFunctions())
                .containsExactly(CryptoFunction.SIGN, CryptoFunction.VERIFY);
        assertThat(merged.getPadding()).isEqualTo(Padding.PKCS1V15);
        assertThat(merged.getPrimitive()).isEqualTo(Primitive.SIGNATURE);
        assertThat(kept.getCryptoProperties().getOid()).isEqualTo("1.2.3");
    }

    @Test
    void leavesADifferentKindOfAssetAlone() {
        final Component kept = new Component();
        final CryptoProperties protocol = new CryptoProperties();
        protocol.setAssetType(AssetType.PROTOCOL);
        kept.setCryptoProperties(protocol);

        CBOMOutputFile.mergeCryptoProperties(kept, algorithm(CryptoFunction.SIGN));

        assertThat(kept.getCryptoProperties()).isSameAs(protocol);
        assertThat(protocol.getAlgorithmProperties()).isNull();
    }

    @Nonnull
    private static Component algorithm(@Nonnull CryptoFunction function) {
        final AlgorithmProperties algorithmProperties = new AlgorithmProperties();
        algorithmProperties.setPrimitive(Primitive.SIGNATURE);
        algorithmProperties.setPadding(Padding.PKCS1V15);
        algorithmProperties.setParameterSetIdentifier("2048");
        algorithmProperties.setCryptoFunctions(new ArrayList<>(List.of(function)));
        final CryptoProperties cryptoProperties = new CryptoProperties();
        cryptoProperties.setAssetType(AssetType.ALGORITHM);
        cryptoProperties.setOid("1.2.3");
        cryptoProperties.setAlgorithmProperties(algorithmProperties);
        final Component component = new Component();
        component.setCryptoProperties(cryptoProperties);
        return component;
    }

    private static void assertNoSingleValuedProperty(@Nullable AlgorithmProperties properties) {
        assertThat(properties).isNotNull();
        assertThat(properties.getPrimitive()).isNull();
        assertThat(properties.getPadding()).isNull();
        assertThat(properties.getParameterSetIdentifier()).isNull();
    }
}
