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
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.algorithms.ECDSA;
import com.ibm.mapper.model.algorithms.Ed25519;
import com.ibm.mapper.model.algorithms.Ed448;
import com.ibm.mapper.model.algorithms.MLDSA;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.SPHINCSPlus;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Maps OpenSSL TLS signature-algorithm names (the {@code SSL_(CTX_)set1_sigalgs_list} argument) to
 * model classes. Handles the legacy {@code ALG+HASH} form (e.g. {@code ECDSA+SHA256}), PQC scheme
 * names (e.g. {@code SLH-DSA-SHA2-256s}, {@code mldsa65}), and the TLS 1.2/1.3 underscore
 * wire-format names (e.g. {@code rsa_pss_rsae_sha256}, {@code ecdsa_secp256r1_sha256}, {@code
 * rsa_pkcs1_sha256}). Unrecognized names return {@link Optional#empty()}; the caller emits them as
 * a raw asset so nothing is dropped.
 */
public final class OpenSslSignatureMapper implements IMapper {

    @Nonnull
    @Override
    public Optional<? extends INode> parse(
            @Nullable String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }

        // Legacy TLS sigalgs use the ALG+HASH spelling (e.g. "ECDSA+SHA256"); the signature
        // algorithm is the part before '+'.
        final String algorithm = str.contains("+") ? str.substring(0, str.indexOf('+')) : str;
        final String normalized = algorithm.trim().toUpperCase();

        if (normalized.startsWith("SLH-DSA") || normalized.startsWith("SLHDSA")) {
            return Optional.of(new SPHINCSPlus(detectionLocation));
        }
        if (normalized.startsWith("ML-DSA") || normalized.startsWith("MLDSA")) {
            return Optional.of(new MLDSA(detectionLocation));
        }
        switch (normalized) {
            case "ECDSA":
                return Optional.of(new ECDSA(detectionLocation));
            case "RSA", "RSA-PSS", "RSA_PSS_RSAE", "RSA_PSS_PSS":
                return Optional.of(new RSA(detectionLocation));
            case "ED25519":
                return Optional.of(new Ed25519(detectionLocation));
            case "ED448":
                return Optional.of(new Ed448(detectionLocation));
            default:
                // fall through to the OpenSSL 1.1.1+/3.x wire-format names below
        }

        // TLS 1.2/1.3 wire-format sigalgs (RFC 8446 §4.2.3, e.g. "rsa_pss_rsae_sha256",
        // "ecdsa_secp256r1_sha256", "rsa_pkcs1_sha256"): underscore-separated, ending in the
        // digest name, with no '+' separator.
        if (normalized.startsWith("RSA_PSS_RSAE_") || normalized.startsWith("RSA_PSS_PSS_")) {
            return Optional.of(new RSA(detectionLocation));
        }
        if (normalized.startsWith("RSA_PKCS1_")) {
            return Optional.of(new RSA(detectionLocation));
        }
        if (normalized.startsWith("ECDSA_")) {
            return Optional.of(new ECDSA(detectionLocation));
        }
        return Optional.empty();
    }
}
