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
package com.ibm.mapper.mapper.pyca;

import com.ibm.mapper.mapper.IMapper;
import com.ibm.mapper.model.EllipticCurveAlgorithm;
import com.ibm.mapper.model.curves.Brainpoolp256r1;
import com.ibm.mapper.model.curves.Brainpoolp384r1;
import com.ibm.mapper.model.curves.Brainpoolp512r1;
import com.ibm.mapper.model.curves.Curve25519;
import com.ibm.mapper.model.curves.Curve448;
import com.ibm.mapper.model.curves.Edwards25519;
import com.ibm.mapper.model.curves.Edwards448;
import com.ibm.mapper.model.curves.Secp192r1;
import com.ibm.mapper.model.curves.Secp224r1;
import com.ibm.mapper.model.curves.Secp256k1;
import com.ibm.mapper.model.curves.Secp256r1;
import com.ibm.mapper.model.curves.Secp384r1;
import com.ibm.mapper.model.curves.Secp521r1;
import com.ibm.mapper.model.curves.Sect163k1;
import com.ibm.mapper.model.curves.Sect163r2;
import com.ibm.mapper.model.curves.Sect233k1;
import com.ibm.mapper.model.curves.Sect233r1;
import com.ibm.mapper.model.curves.Sect283k1;
import com.ibm.mapper.model.curves.Sect283r1;
import com.ibm.mapper.model.curves.Sect409k1;
import com.ibm.mapper.model.curves.Sect409r1;
import com.ibm.mapper.model.curves.Sect571k1;
import com.ibm.mapper.model.curves.Sect571r1;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public final class PycaCurveMapper implements IMapper {

    @Nonnull
    @Override
    public Optional<EllipticCurveAlgorithm> parse(
            @Nullable String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }

        @Nonnull String curve = str;
        return switch (curve.toUpperCase().trim()) {
            case "SECP192R1", "PRIME192V1", "P-192", "P192", "NIST P-192" ->
                    Optional.of(new EllipticCurveAlgorithm(new Secp192r1(detectionLocation)));
            case "SECP224R1", "PRIME224V1", "P-224", "P224", "NIST P-224" ->
                    Optional.of(new EllipticCurveAlgorithm(new Secp224r1(detectionLocation)));
            case "SECP256R1", "PRIME256V1", "P-256", "P256", "NIST P-256" ->
                    Optional.of(new EllipticCurveAlgorithm(new Secp256r1(detectionLocation)));
            case "SECP384R1", "PRIME384V1", "P-384", "P384", "NIST P-384" ->
                    Optional.of(new EllipticCurveAlgorithm(new Secp384r1(detectionLocation)));
            case "SECP521R1", "PRIME521V1", "P-521", "P521", "NIST P-521" ->
                    Optional.of(new EllipticCurveAlgorithm(new Secp521r1(detectionLocation)));
            case "SECP256K1" ->
                    Optional.of(new EllipticCurveAlgorithm(new Secp256k1(detectionLocation)));
            case "CURVE25519" ->
                    Optional.of(new EllipticCurveAlgorithm(new Curve25519(detectionLocation)));
            case "ED25519" ->
                    Optional.of(new EllipticCurveAlgorithm(new Edwards25519(detectionLocation)));
            case "CURVE448" ->
                    Optional.of(new EllipticCurveAlgorithm(new Curve448(detectionLocation)));
            case "ED448" ->
                    Optional.of(new EllipticCurveAlgorithm(new Edwards448(detectionLocation)));
            case "BRAINPOOLP256R1" ->
                    Optional.of(new EllipticCurveAlgorithm(new Brainpoolp256r1(detectionLocation)));
            case "BRAINPOOLP384R1" ->
                    Optional.of(new EllipticCurveAlgorithm(new Brainpoolp384r1(detectionLocation)));
            case "BRAINPOOLP512R1" ->
                    Optional.of(new EllipticCurveAlgorithm(new Brainpoolp512r1(detectionLocation)));
            case "SECT571K1" ->
                    Optional.of(new EllipticCurveAlgorithm(new Sect571k1(detectionLocation)));
            case "SECT409K1" ->
                    Optional.of(new EllipticCurveAlgorithm(new Sect409k1(detectionLocation)));
            case "SECT283K1" ->
                    Optional.of(new EllipticCurveAlgorithm(new Sect283k1(detectionLocation)));
            case "SECT233K1" ->
                    Optional.of(new EllipticCurveAlgorithm(new Sect233k1(detectionLocation)));
            case "SECT163K1" ->
                    Optional.of(new EllipticCurveAlgorithm(new Sect163k1(detectionLocation)));
            case "SECT571R1" ->
                    Optional.of(new EllipticCurveAlgorithm(new Sect571r1(detectionLocation)));
            case "SECT409R1" ->
                    Optional.of(new EllipticCurveAlgorithm(new Sect409r1(detectionLocation)));
            case "SECT283R1" ->
                    Optional.of(new EllipticCurveAlgorithm(new Sect283r1(detectionLocation)));
            case "SECT233R1" ->
                    Optional.of(new EllipticCurveAlgorithm(new Sect233r1(detectionLocation)));
            case "SECT163R2" ->
                    Optional.of(new EllipticCurveAlgorithm(new Sect163r2(detectionLocation)));
            default -> Optional.empty();
        };
    }
}
