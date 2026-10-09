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
package com.ibm.mapper.mapper.ssl;

import com.ibm.mapper.mapper.IMapper;
import com.ibm.mapper.mapper.openssl.OpenSslCurveMapper;
import com.ibm.mapper.mapper.openssl.OpenSslMessageDigestMapper;
import com.ibm.mapper.mapper.openssl.OpenSslSignatureAlgorithmMapper;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Maps OpenSSL TLS signature-algorithm names (the {@code SSL_(CTX_)set1_sigalgs_list} argument) to
 * the signature scheme with its digest and, for ECDSA, its curve. Handles the legacy {@code
 * ALG+HASH} form (e.g. {@code ECDSA+SHA256}, {@code RSA-PSS+SHA256}), the TLS 1.2/1.3 wire-format
 * names (e.g. {@code rsa_pss_rsae_sha256}, {@code ecdsa_secp256r1_sha256}, {@code
 * rsa_pkcs1_sha256}), and the scheme names without a digest (e.g. {@code ed25519}, {@code mldsa65},
 * {@code SLH-DSA-SHA2-256s}). In TLS, an RSA signature that is not RSA-PSS uses PKCS#1 v1.5
 * padding. Unrecognized names return {@link Optional#empty()}; the caller emits them as a raw asset
 * so nothing is dropped.
 */
public final class OpenSslSignatureMapper implements IMapper {

    @Nonnull
    @Override
    public Optional<? extends INode> parse(
            @Nullable String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }
        final String name = str.trim().toUpperCase();
        final int plus = name.indexOf('+');
        if (plus >= 0) {
            return scheme(name.substring(0, plus), name.substring(plus + 1), detectionLocation);
        }
        if (name.startsWith("RSA_PSS_RSAE_") || name.startsWith("RSA_PSS_PSS_")) {
            return scheme("RSA-PSS", afterLastUnderscore(name), detectionLocation);
        }
        if (name.startsWith("RSA_PKCS1_")) {
            return scheme("RSA", afterLastUnderscore(name), detectionLocation);
        }
        if (name.startsWith("ECDSA_")) {
            return ecdsa(str.trim().substring("ECDSA_".length()), detectionLocation);
        }
        if (name.startsWith("MLDSA")) {
            return signature("ML-DSA-" + name.substring("MLDSA".length()), detectionLocation);
        }
        return signature(name, detectionLocation);
    }

    /** A scheme with its digest: in TLS, an RSA scheme other than RSA-PSS is PKCS#1 v1.5. */
    @Nonnull
    private static Optional<? extends INode> scheme(
            @Nonnull String scheme,
            @Nonnull String digest,
            @Nonnull DetectionLocation detectionLocation) {
        final String algorithm = "RSA".equals(scheme.trim()) ? "RSA-PKCS1" : scheme.trim();
        final Optional<? extends INode> signature = signature(algorithm, detectionLocation);
        signature.ifPresent(
                node ->
                        new OpenSslMessageDigestMapper()
                                .parse(digest.trim(), detectionLocation)
                                .filter(MessageDigest.class::isInstance)
                                .ifPresent(node::put));
        return signature;
    }

    /**
     * An ECDSA wire-format name after its {@code ecdsa_} prefix: the curve, when named, and the
     * digest, e.g. {@code secp256r1_sha256}, {@code brainpoolP256r1tls13_sha256} or {@code sha1}.
     */
    @Nonnull
    private static Optional<? extends INode> ecdsa(
            @Nonnull String curveAndDigest, @Nonnull DetectionLocation detectionLocation) {
        final int underscore = curveAndDigest.lastIndexOf('_');
        final Optional<? extends INode> ecdsa =
                scheme("ECDSA", curveAndDigest.substring(underscore + 1), detectionLocation);
        if (underscore > 0) {
            final String curve =
                    curveAndDigest.substring(0, underscore).replaceFirst("(?i)tls13$", "");
            ecdsa.ifPresent(
                    node ->
                            new OpenSslCurveMapper()
                                    .parse(curve, detectionLocation)
                                    .ifPresent(node::put));
        }
        return ecdsa;
    }

    @Nonnull
    private static Optional<? extends INode> signature(
            @Nonnull String name, @Nonnull DetectionLocation detectionLocation) {
        return new OpenSslSignatureAlgorithmMapper().parse(name, detectionLocation);
    }

    @Nonnull
    private static String afterLastUnderscore(@Nonnull String name) {
        return name.substring(name.lastIndexOf('_') + 1);
    }
}
