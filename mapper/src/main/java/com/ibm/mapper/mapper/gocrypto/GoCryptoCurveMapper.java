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
package com.ibm.mapper.mapper.gocrypto;

import com.ibm.mapper.mapper.IMapper;
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.curves.Secp224r1;
import com.ibm.mapper.model.curves.Secp256r1;
import com.ibm.mapper.model.curves.Secp384r1;
import com.ibm.mapper.model.curves.Secp521r1;
import com.ibm.mapper.utils.DetectionLocation;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Optional;

/**
 * Maps Go crypto/elliptic curve names to the corresponding elliptic curve model classes.
 *
 * <p>Go's crypto/elliptic package provides NIST P-curves:
 *
 * <ul>
 *   <li>P-224 → secp224r1
 *   <li>P-256 → secp256r1
 *   <li>P-384 → secp384r1
 *   <li>P-521 → secp521r1
 * </ul>
 */
public final class GoCryptoCurveMapper implements IMapper {

    @Nonnull
    @Override
    public Optional<? extends EllipticCurve> parse(
            @Nullable String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }

        return switch (str.toUpperCase().trim()) {
            case "P-224" ->
                    Optional.of(new Secp224r1(detectionLocation));
            case "P-256" ->
                    Optional.of(new Secp256r1(detectionLocation));
            case "P-384" ->
                    Optional.of(new Secp384r1(detectionLocation));
            case "P-521" ->
                    Optional.of(new Secp521r1(detectionLocation));
            default -> Optional.empty();
        };
    }
}
