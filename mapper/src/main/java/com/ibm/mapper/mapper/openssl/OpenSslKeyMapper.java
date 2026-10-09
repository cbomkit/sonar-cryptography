/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2026 PQCA
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
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.EllipticCurveAlgorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.algorithms.DH;
import com.ibm.mapper.model.algorithms.DSA;
import com.ibm.mapper.model.algorithms.Ed25519;
import com.ibm.mapper.model.algorithms.Ed448;
import com.ibm.mapper.model.algorithms.MLDSA;
import com.ibm.mapper.model.algorithms.MLKEM;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.RSAssaPSS;
import com.ibm.mapper.model.algorithms.SPHINCSPlus;
import com.ibm.mapper.model.algorithms.SecP256r1MLKEM768;
import com.ibm.mapper.model.algorithms.SecP384r1MLKEM1024;
import com.ibm.mapper.model.algorithms.X25519;
import com.ibm.mapper.model.algorithms.X25519MLKEM768;
import com.ibm.mapper.model.algorithms.X448;
import com.ibm.mapper.model.algorithms.X448MLKEM1024;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Maps the OpenSSL key names to the model: the key types of {@code EVP_PKEY_CTX_new_id}, {@code
 * EVP_PKEY_CTX_new_from_name} and {@code EVP_PKEY_Q_keygen}, the named curves of an EC key, the DH
 * groups, and the names the key detection rules give a key with its size (e.g. {@code RSA-3072},
 * {@code DSA-2048}, {@code EC-P256}).
 */
public class OpenSslKeyMapper implements IMapper {

    /** The prefix of the name of an EC key on a named curve, e.g. {@code EC-P256}. */
    private static final String EC_CURVE_PREFIX = "EC-";

    @Nonnull
    @Override
    public Optional<? extends INode> parse(
            @Nullable final String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }
        final String algorithmName = str.toUpperCase().trim();

        // EC key on a named curve (e.g. EC_KEY_new_by_curve_name, EVP_PKEY_CTX_set_group_name),
        // usable for ECDSA and ECDH
        final Optional<EllipticCurve> curve = parseCurve(algorithmName, detectionLocation);
        if (curve.isPresent()) {
            return curve.map(EllipticCurveAlgorithm::new);
        }

        // RSA key length (EVP_PKEY_CTX_set_rsa_keygen_bits) — any bit-length the code sets,
        // not just a fixed whitelist
        if (algorithmName.startsWith("RSA-") && !algorithmName.equals("RSA-PSS")) {
            Integer bits = parseBits(algorithmName, "RSA-");
            if (bits != null) {
                return Optional.of(new RSA(bits, detectionLocation));
            }
        }

        // DSA parameter length (EVP_PKEY_CTX_set_dsa_paramgen_bits, DSA_generate_parameters)
        if (algorithmName.startsWith("DSA-")) {
            Integer bits = parseBits(algorithmName, "DSA-");
            if (bits != null) {
                final DSA dsa = new DSA(detectionLocation);
                dsa.put(new KeyLength(bits, detectionLocation));
                return Optional.of(dsa);
            }
        }

        return switch (algorithmName) {
            // RSA
            case "RSA" -> Optional.of(new RSA(detectionLocation));
            // a key restricted to RSA-PSS signatures
            case "RSA-PSS" -> Optional.of(new RSAssaPSS(detectionLocation));

            // DSA
            case "DSA" -> Optional.of(new DSA(detectionLocation));

            // EC
            case "EC" -> Optional.of(new EllipticCurveAlgorithm(detectionLocation));

            // DH
            case "DH" -> Optional.of(new DH(detectionLocation));
            case "DH-2048" -> Optional.of(finiteFieldDh(2048, detectionLocation));
            case "DH-3072" -> Optional.of(finiteFieldDh(3072, detectionLocation));
            case "DH-4096" -> Optional.of(finiteFieldDh(4096, detectionLocation));
            // RFC 5114 groups (DH_get_1024_160 etc.): prime size and subgroup size
            case "DH-1024-160" -> Optional.of(finiteFieldDh(1024, detectionLocation));
            case "DH-2048-224", "DH-2048-256" ->
                    Optional.of(finiteFieldDh(2048, detectionLocation));

            // EdDSA
            case "ED25519" -> Optional.of(new Ed25519(detectionLocation));
            case "ED448" -> Optional.of(new Ed448(detectionLocation));

            // X25519/X448
            case "X25519" -> Optional.of(new X25519(detectionLocation));
            case "X448" -> Optional.of(new X448(detectionLocation));

            // ML-KEM (Post-Quantum)
            case "ML-KEM-512" -> Optional.of(new MLKEM(512, detectionLocation));
            case "ML-KEM-768" -> Optional.of(new MLKEM(768, detectionLocation));
            case "ML-KEM-1024" -> Optional.of(new MLKEM(1024, detectionLocation));

            // ML-DSA (Post-Quantum)
            case "ML-DSA-44" -> Optional.of(new MLDSA(44, detectionLocation));
            case "ML-DSA-65" -> Optional.of(new MLDSA(65, detectionLocation));
            case "ML-DSA-87" -> Optional.of(new MLDSA(87, detectionLocation));

            // SLH-DSA (Post-Quantum)
            case "SLH-DSA-SHA2-128F" ->
                    Optional.of(new SPHINCSPlus("SHA2-128F", detectionLocation));
            case "SLH-DSA-SHA2-128S" ->
                    Optional.of(new SPHINCSPlus("SHA2-128S", detectionLocation));
            case "SLH-DSA-SHAKE-128F" ->
                    Optional.of(new SPHINCSPlus("SHAKE-128F", detectionLocation));
            case "SLH-DSA-SHAKE-128S" ->
                    Optional.of(new SPHINCSPlus("SHAKE-128S", detectionLocation));
            case "SLH-DSA-SHA2-192F" ->
                    Optional.of(new SPHINCSPlus("SHA2-192F", detectionLocation));
            case "SLH-DSA-SHA2-192S" ->
                    Optional.of(new SPHINCSPlus("SHA2-192S", detectionLocation));
            case "SLH-DSA-SHAKE-192F" ->
                    Optional.of(new SPHINCSPlus("SHAKE-192F", detectionLocation));
            case "SLH-DSA-SHAKE-192S" ->
                    Optional.of(new SPHINCSPlus("SHAKE-192S", detectionLocation));
            case "SLH-DSA-SHA2-256F" ->
                    Optional.of(new SPHINCSPlus("SHA2-256F", detectionLocation));
            case "SLH-DSA-SHA2-256S" ->
                    Optional.of(new SPHINCSPlus("SHA2-256S", detectionLocation));
            case "SLH-DSA-SHAKE-256F" ->
                    Optional.of(new SPHINCSPlus("SHAKE-256F", detectionLocation));
            case "SLH-DSA-SHAKE-256S" ->
                    Optional.of(new SPHINCSPlus("SHAKE-256S", detectionLocation));

            // Hybrid Post-Quantum KEMs (PQC + Classical)
            case "X25519MLKEM768" -> Optional.of(new X25519MLKEM768(detectionLocation));
            case "X448MLKEM1024" -> Optional.of(new X448MLKEM1024(detectionLocation));
            case "SECP256R1MLKEM768" -> Optional.of(new SecP256r1MLKEM768(detectionLocation));
            case "SECP384R1MLKEM1024" -> Optional.of(new SecP384r1MLKEM1024(detectionLocation));

            // SM2
            case "SM2" -> Optional.of(new com.ibm.mapper.model.algorithms.SM2(detectionLocation));

            default -> Optional.empty();
        };
    }

    /** A named curve, e.g. {@code EC-P256} (as given to {@code EVP_PKEY_CTX_set_group_name}). */
    @Nonnull
    public Optional<EllipticCurve> parseCurve(
            @Nullable final String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }
        final String curveName = str.toUpperCase().trim();
        if (!curveName.startsWith(EC_CURVE_PREFIX)) {
            return Optional.empty();
        }
        return new OpenSslCurveMapper()
                .parse(curveName.substring(EC_CURVE_PREFIX.length()), detectionLocation)
                .map(curve -> curve);
    }

    @Nullable private static Integer parseBits(@Nonnull String algorithmName, @Nonnull String prefix) {
        try {
            int bits = Integer.parseInt(algorithmName.substring(prefix.length()));
            return bits > 0 ? bits : null;
        } catch (NumberFormatException e) {
            return null;
        }
    }

    @Nonnull
    private static DH finiteFieldDh(int primeBits, @Nonnull DetectionLocation detectionLocation) {
        DH dh = new DH(PublicKeyEncryption.class, detectionLocation);
        dh.put(new KeyLength(primeBits, detectionLocation));
        return dh;
    }
}
