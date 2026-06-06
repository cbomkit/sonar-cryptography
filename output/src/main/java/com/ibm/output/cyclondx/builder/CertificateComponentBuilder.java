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

import com.ibm.mapper.model.Certificate;
import java.util.List;
import java.util.UUID;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.component.crypto.CertificateProperties;
import org.cyclonedx.model.component.crypto.CryptoProperties;
import org.cyclonedx.model.component.crypto.enums.AssetType;
import org.cyclonedx.model.component.evidence.Occurrence;

public class CertificateComponentBuilder implements ICertificateComponentBuilder {

    @Nonnull private final Component component;
    @Nonnull private final CryptoProperties cryptoProperties;
    @Nonnull private final CertificateProperties certificateProperties;

    @Nonnull private UUID uuid = UUID.randomUUID();

    protected CertificateComponentBuilder() {
        this.component = new Component();
        this.cryptoProperties = new CryptoProperties();
        this.certificateProperties = new CertificateProperties();
    }

    public CertificateComponentBuilder(
            @Nonnull Component component,
            @Nonnull CryptoProperties cryptoProperties,
            @Nonnull CertificateProperties certificateProperties,
            @Nonnull UUID uuid) {
        this.component = component;
        this.cryptoProperties = cryptoProperties;
        this.certificateProperties = certificateProperties;
        this.uuid = uuid;
    }

    @Nonnull
    public static ICertificateComponentBuilder create() {
        return new CertificateComponentBuilder();
    }

    @Nonnull
    @Override
    public ICertificateComponentBuilder certificate(@Nullable Certificate certificate) {
        if (certificate == null) {
            return new CertificateComponentBuilder(
                    component, cryptoProperties, certificateProperties, uuid);
        }

        this.component.setName(certificate.asString() + "@" + this.uuid);
        this.certificateProperties.setCertificateFormat(certificate.getFormat());

        return new CertificateComponentBuilder(
                component, cryptoProperties, certificateProperties, uuid);
    }

    @Nonnull
    @Override
    public ICertificateComponentBuilder occurrences(@Nullable Occurrence... occurrences) {
        if (occurrences == null) {
            return new CertificateComponentBuilder(
                    component, cryptoProperties, certificateProperties, uuid);
        }
        final Evidence evidence = new Evidence();
        evidence.setOccurrences(List.of(occurrences));
        this.component.setEvidence(evidence);
        return new CertificateComponentBuilder(
                component, cryptoProperties, certificateProperties, uuid);
    }

    @Nonnull
    @Override
    public Component build() {
        this.cryptoProperties.setAssetType(AssetType.CERTIFICATE);
        this.cryptoProperties.setCertificateProperties(certificateProperties);

        this.component.setType(Component.Type.CRYPTOGRAPHIC_ASSET);
        this.component.setCryptoProperties(this.cryptoProperties);
        this.component.setBomRef(this.uuid.toString());

        return this.component;
    }
}
