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
package com.ibm.output.cyclondx.builder;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.CipherSuite;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Identifier;
import com.ibm.mapper.model.Protocol;
import com.ibm.mapper.model.collections.CipherSuiteCollection;
import com.ibm.mapper.model.protocol.IKE;
import com.ibm.mapper.model.protocol.IPSec;
import com.ibm.mapper.model.protocol.TLS;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.function.BiFunction;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.component.crypto.CryptoProperties;
import org.cyclonedx.model.component.crypto.ProtocolProperties;
import org.cyclonedx.model.component.crypto.RelatedCryptographicAsset;
import org.cyclonedx.model.component.crypto.enums.AssetType;
import org.cyclonedx.model.component.crypto.enums.ProtocolType;
import org.cyclonedx.model.component.evidence.Occurrence;

public class ProtocolComponentBuilder implements IProtocolComponentBuilder {
    @Nonnull private final Component component;
    @Nonnull private final CryptoProperties cryptoProperties;
    @Nonnull private final ProtocolProperties protocolProperties;
    @Nonnull private final BiFunction<String, Algorithm, String> algorithmComponentBuilder;

    protected ProtocolComponentBuilder(
            @Nonnull BiFunction<String, Algorithm, String> algorithmComponentBuilder) {
        this.component = new Component();
        this.component.setBomRef(UUID.randomUUID().toString());
        this.cryptoProperties = new CryptoProperties();
        this.protocolProperties = new ProtocolProperties();
        this.algorithmComponentBuilder = algorithmComponentBuilder;
    }

    private ProtocolComponentBuilder(
            @Nonnull Component component,
            @Nonnull CryptoProperties cryptoProperties,
            @Nonnull ProtocolProperties protocolProperties,
            @Nonnull BiFunction<String, Algorithm, String> algorithmComponentBuilder) {
        this.component = component;
        this.cryptoProperties = cryptoProperties;
        this.protocolProperties = protocolProperties;
        this.algorithmComponentBuilder = algorithmComponentBuilder;
    }

    @Nonnull
    public static IProtocolComponentBuilder create(
            @Nonnull BiFunction<String, Algorithm, String> algorithmComponentBuilder) {
        return new ProtocolComponentBuilder(algorithmComponentBuilder);
    }

    @Nonnull
    @Override
    public IProtocolComponentBuilder name(@Nullable Protocol name) {
        if (name == null) {
            return new ProtocolComponentBuilder(
                    component, cryptoProperties, protocolProperties, algorithmComponentBuilder);
        }

        this.component.setName(name.asString());
        return new ProtocolComponentBuilder(
                component, cryptoProperties, protocolProperties, algorithmComponentBuilder);
    }

    @Nonnull
    @Override
    public IProtocolComponentBuilder type(@Nullable Protocol type) {
        if (type == null) {
            protocolProperties.setType(ProtocolType.UNKNOWN);
            return new ProtocolComponentBuilder(
                    component, cryptoProperties, protocolProperties, algorithmComponentBuilder);
        }

        if (type instanceof TLS) {
            protocolProperties.setType(ProtocolType.TLS);
        } else if (type instanceof IPSec) {
            protocolProperties.setType(ProtocolType.IPSEC);
        } else if (type instanceof IKE) {
            protocolProperties.setType(ProtocolType.IKE);
        } else {
            protocolProperties.setType(ProtocolType.OTHER);
        }

        return new ProtocolComponentBuilder(
                component, cryptoProperties, protocolProperties, algorithmComponentBuilder);
    }

    @Nonnull
    @Override
    public IProtocolComponentBuilder version(@Nullable INode version) {
        if (version == null) {
            return new ProtocolComponentBuilder(
                    component, cryptoProperties, protocolProperties, algorithmComponentBuilder);
        }
        protocolProperties.setVersion(version.asString());
        return new ProtocolComponentBuilder(
                component, cryptoProperties, protocolProperties, algorithmComponentBuilder);
    }

    @Nonnull
    @Override
    public IProtocolComponentBuilder cipherSuites(@Nullable INode node) {
        if (node == null) {
            return new ProtocolComponentBuilder(
                    component, cryptoProperties, protocolProperties, algorithmComponentBuilder);
        }

        if (node instanceof CipherSuiteCollection cipherSuiteCollection) {
            List<org.cyclonedx.model.component.crypto.CipherSuite> suites = new ArrayList<>();
            for (CipherSuite cipherSuite : cipherSuiteCollection.getCollection()) {
                final org.cyclonedx.model.component.crypto.CipherSuite suite =
                        new org.cyclonedx.model.component.crypto.CipherSuite();
                // name
                suite.setName(cipherSuite.getName());
                // algorithms
                cipherSuite
                        .getAssetCollection()
                        .ifPresent(
                                assetCollection -> {
                                    final List<String> algorithmRefs = new ArrayList<>();
                                    for (final INode asset : assetCollection.getCollection()) {
                                        if (asset instanceof Algorithm algorithm) {
                                            final String ref =
                                                    this.algorithmComponentBuilder.apply(
                                                            component.getBomRef(), algorithm);
                                            algorithmRefs.add(ref);
                                        }
                                    }
                                    suite.setAlgorithms(algorithmRefs);
                                });
                // identifiers
                cipherSuite
                        .getIdentifierCollection()
                        .ifPresent(
                                identifierCollection -> {
                                    final List<String> identifiers = new ArrayList<>();
                                    for (final Identifier identifier :
                                            identifierCollection.getCollection()) {
                                        identifiers.add(identifier.getValue());
                                    }
                                    suite.setIdentifiers(identifiers);
                                });
                suites.add(suite);
            }
            protocolProperties.setCipherSuites(suites);
        }

        return new ProtocolComponentBuilder(
                component, cryptoProperties, protocolProperties, algorithmComponentBuilder);
    }

    @Nonnull
    @Override
    public IProtocolComponentBuilder relatedCryptographicAssets(
            @Nullable List<RelatedCryptographicAsset> assets) {
        if (assets == null) {
            return new ProtocolComponentBuilder(
                    component, cryptoProperties, protocolProperties, algorithmComponentBuilder);
        }
        this.protocolProperties.setRelatedCryptographicAssets(assets);
        return new ProtocolComponentBuilder(
                component, cryptoProperties, protocolProperties, algorithmComponentBuilder);
    }

    @Nonnull
    @Override
    public IProtocolComponentBuilder occurrences(@Nullable Occurrence... occurrences) {
        if (occurrences == null) {
            return new ProtocolComponentBuilder(
                    component, cryptoProperties, protocolProperties, algorithmComponentBuilder);
        }
        final Evidence evidence = new Evidence();
        evidence.setOccurrences(List.of(occurrences));
        this.component.setEvidence(evidence);
        return new ProtocolComponentBuilder(
                component, cryptoProperties, protocolProperties, algorithmComponentBuilder);
    }

    @Nonnull
    @Override
    public Component build() {
        this.cryptoProperties.setAssetType(AssetType.PROTOCOL);
        this.cryptoProperties.setProtocolProperties(protocolProperties);

        this.component.setType(Component.Type.CRYPTOGRAPHIC_ASSET);
        this.component.setCryptoProperties(this.cryptoProperties);

        return this.component;
    }
}
