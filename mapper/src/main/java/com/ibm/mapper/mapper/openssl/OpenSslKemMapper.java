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
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.ChaCha20Poly1305;
import com.ibm.mapper.model.algorithms.DHKEM;
import com.ibm.mapper.model.algorithms.ECDH;
import com.ibm.mapper.model.algorithms.HKDF;
import com.ibm.mapper.model.algorithms.HPKE;
import com.ibm.mapper.model.algorithms.RSASVE;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.algorithms.X25519;
import com.ibm.mapper.model.algorithms.X448;
import com.ibm.mapper.model.mode.GCM;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Maps the OpenSSL key encapsulation names (the names accepted by {@code EVP_KEM_fetch}) and the
 * HPKE suites {@code "<KEM>,<KDF>,<AEAD>"} to the model. The other KEM names are key agreement
 * names, mapped by {@link OpenSslKeyAgreementMapper}.
 */
public class OpenSslKemMapper implements IMapper {

    @Nonnull
    @Override
    public Optional<? extends INode> parse(
            @Nullable final String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }
        return switch (str.toUpperCase().trim()) {
            // RSA secret value encapsulation (RSASVE, NIST SP 800-56B)
            case "RSA" -> Optional.of(new RSASVE(detectionLocation));
            // DHKEM (RFC 9180) over the curve of the key
            case "EC" -> Optional.of(new DHKEM(new ECDH(detectionLocation), detectionLocation));
            case "X25519" ->
                    Optional.of(new DHKEM(new X25519(detectionLocation), detectionLocation));
            case "X448" -> Optional.of(new DHKEM(new X448(detectionLocation), detectionLocation));
            default -> new OpenSslKeyAgreementMapper().parse(str, detectionLocation);
        };
    }

    /**
     * An HPKE suite {@code "<KEM>,<KDF>,<AEAD>"}, e.g. {@code "X25519,HKDF-SHA256,AES-128-GCM"}.
     * The export-only AEAD has no cipher.
     */
    @Nonnull
    public Optional<HPKE> parseHpkeSuite(
            @Nullable final String suite, @Nonnull DetectionLocation detectionLocation) {
        if (suite == null) {
            return Optional.empty();
        }
        final String[] parts = suite.toUpperCase().trim().split(",");
        if (parts.length != 3) {
            return Optional.empty();
        }
        final Optional<INode> kem =
                switch (parts[0]) {
                    case "P-256" -> Optional.of(dhkemOverCurve("secp256r1", detectionLocation));
                    case "P-384" -> Optional.of(dhkemOverCurve("secp384r1", detectionLocation));
                    case "P-521" -> Optional.of(dhkemOverCurve("secp521r1", detectionLocation));
                    case "X25519" ->
                            Optional.of(
                                    new DHKEM(new X25519(detectionLocation), detectionLocation));
                    case "X448" ->
                            Optional.of(new DHKEM(new X448(detectionLocation), detectionLocation));
                    default -> Optional.empty();
                };
        final Optional<INode> kdf =
                switch (parts[1]) {
                    case "HKDF-SHA256" -> Optional.of(new HKDF(new SHA2(256, detectionLocation)));
                    case "HKDF-SHA384" -> Optional.of(new HKDF(new SHA2(384, detectionLocation)));
                    case "HKDF-SHA512" -> Optional.of(new HKDF(new SHA2(512, detectionLocation)));
                    default -> Optional.empty();
                };
        final Optional<INode> aead =
                switch (parts[2]) {
                    case "AES-128-GCM" ->
                            Optional.of(
                                    new AES(128, new GCM(detectionLocation), detectionLocation));
                    case "AES-256-GCM" ->
                            Optional.of(
                                    new AES(256, new GCM(detectionLocation), detectionLocation));
                    case "CHACHA20-POLY1305" ->
                            Optional.of(new ChaCha20Poly1305(detectionLocation));
                    default -> Optional.empty();
                };
        if (kem.isEmpty() || kdf.isEmpty()) {
            return Optional.empty();
        }
        final HPKE hpke = new HPKE(detectionLocation);
        hpke.put(kem.get());
        hpke.put(kdf.get());
        aead.ifPresent(hpke::put);
        return Optional.of(hpke);
    }

    @Nonnull
    private static DHKEM dhkemOverCurve(
            @Nonnull String curve, @Nonnull DetectionLocation detectionLocation) {
        return new DHKEM(new ECDH(new EllipticCurve(curve, detectionLocation)), detectionLocation);
    }
}
