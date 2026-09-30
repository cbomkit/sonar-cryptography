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
package com.ibm.mapper.mapper.openssl;

import com.ibm.mapper.mapper.IMapper;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.algorithms.DSA;
import com.ibm.mapper.model.algorithms.ECDSA;
import com.ibm.mapper.model.algorithms.Ed25519;
import com.ibm.mapper.model.algorithms.Ed448;
import com.ibm.mapper.model.algorithms.MLDSA;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.RSAssaPSS;
import com.ibm.mapper.model.algorithms.SM2;
import com.ibm.mapper.model.algorithms.SPHINCSPlus;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Maps the OpenSSL signature names to the model: the names accepted by {@code EVP_SIGNATURE_fetch},
 * the RSA signature schemes selected by an RSA padding ({@code RSA-PKCS1}, {@code RSA-X931}, {@code
 * RSA-NO-PADDING}), and the names the signature detection rules give a scheme with its digest,
 * {@code <scheme>-<digest>} (e.g. {@code RSA-SHA256}, {@code RSA-PSS-SHA384}, {@code
 * ECDSA-SHA3-256}, {@code RSA-MD5-SHA1}). The digest is mapped by {@link
 * OpenSslMessageDigestMapper}.
 */
public class OpenSslSignatureAlgorithmMapper implements IMapper {

    @Nonnull
    @Override
    public Optional<? extends INode> parse(
            @Nullable final String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }
        final String name = str.toUpperCase().trim();
        return switch (name) {
            case "RSA-PKCS1" -> Optional.of(OpenSslRsaSignatureSchemes.pkcs1v15(detectionLocation));
            case "RSA-X931" -> Optional.of(OpenSslRsaSignatureSchemes.x931(detectionLocation));
            case "RSA-NO-PADDING" ->
                    Optional.of(OpenSslRsaSignatureSchemes.withoutPadding(detectionLocation));
            case "RSA" -> Optional.of(new RSA(Signature.class, detectionLocation));
            case "RSA-PSS" -> Optional.of(new RSAssaPSS(detectionLocation));
            case "DSA" -> Optional.of(new DSA(detectionLocation));
            case "ECDSA" -> Optional.of(new ECDSA(detectionLocation));
            case "ED25519" -> Optional.of(new Ed25519(detectionLocation));
            case "ED448" -> Optional.of(new Ed448(detectionLocation));
            case "SM2" -> Optional.of(new SM2(detectionLocation));
            case "ML-DSA-44" -> Optional.of(new MLDSA(44, detectionLocation));
            case "ML-DSA-65" -> Optional.of(new MLDSA(65, detectionLocation));
            case "ML-DSA-87" -> Optional.of(new MLDSA(87, detectionLocation));
            default -> withParameter(name, detectionLocation);
        };
    }

    /** A scheme followed by its digest, e.g. {@code RSA-SHA256}, or an SLH-DSA parameter set. */
    @Nonnull
    private static Optional<? extends INode> withParameter(
            @Nonnull String name, @Nonnull DetectionLocation detectionLocation) {
        if (name.startsWith("SLH-DSA-")) {
            return Optional.of(
                    new SPHINCSPlus(name.substring("SLH-DSA-".length()), detectionLocation));
        }
        // RSA-PSS before RSA, as both are prefixes of an RSA-PSS name
        if (name.startsWith("RSA-PSS-")) {
            final RSAssaPSS rsaPss = new RSAssaPSS(detectionLocation);
            digest(name, "RSA-PSS-", detectionLocation).ifPresent(rsaPss::put);
            return Optional.of(rsaPss);
        }
        if (name.startsWith("RSA-")) {
            final RSA rsa = new RSA(Signature.class, detectionLocation);
            digest(name, "RSA-", detectionLocation).ifPresent(rsa::put);
            return Optional.of(rsa);
        }
        if (name.startsWith("DSA-")) {
            return Optional.of(
                    digest(name, "DSA-", detectionLocation)
                            .map(DSA::new)
                            .orElseGet(() -> new DSA(detectionLocation)));
        }
        if (name.startsWith("ECDSA-")) {
            final ECDSA ecdsa = new ECDSA(detectionLocation);
            digest(name, "ECDSA-", detectionLocation).ifPresent(ecdsa::put);
            return Optional.of(ecdsa);
        }
        return Optional.empty();
    }

    /** The digest named after the scheme prefix. */
    @Nonnull
    private static Optional<MessageDigest> digest(
            @Nonnull String name,
            @Nonnull String schemePrefix,
            @Nonnull DetectionLocation detectionLocation) {
        return new OpenSslMessageDigestMapper()
                .parse(name.substring(schemePrefix.length()), detectionLocation)
                .map(MessageDigest.class::cast);
    }
}
