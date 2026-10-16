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
package com.ibm.mapper.mapper.pyca;

import com.ibm.mapper.mapper.IMapper;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.EllipticCurveAlgorithm;
import com.ibm.mapper.model.algorithms.DH;
import com.ibm.mapper.model.algorithms.DSA;
import com.ibm.mapper.model.algorithms.Ed25519;
import com.ibm.mapper.model.algorithms.Ed448;
import com.ibm.mapper.model.algorithms.ElGamal;
import com.ibm.mapper.model.algorithms.Fernet;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.curves.Curve25519;
import com.ibm.mapper.model.curves.Curve448;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public final class PycaKeyBasedAlgorithmMapper implements IMapper {

    @Override
    public @Nonnull Optional<Algorithm> parse(
            @Nullable String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }

        return switch (str.toUpperCase().trim()) {
            case "RSA" -> Optional.of(new RSA(detectionLocation));
            case "DSA" -> Optional.of(new DSA(detectionLocation));
            case "DH" -> Optional.of(new DH(detectionLocation));
            case "EC" -> Optional.of(new EllipticCurveAlgorithm(detectionLocation));
            case "CURVE25519" ->
                    Optional.of(new EllipticCurveAlgorithm(new Curve25519(detectionLocation)));
            case "CURVE448" ->
                    Optional.of(new EllipticCurveAlgorithm(new Curve448(detectionLocation)));
            case "ED25519" -> Optional.of(new Ed25519(detectionLocation));
            case "ED448" -> Optional.of(new Ed448(detectionLocation));
            case "ELGAMAL" -> Optional.of(new ElGamal(detectionLocation));
            case "FERNET" -> Optional.of(new Fernet(detectionLocation));
            default -> Optional.empty();
        };
    }
}
