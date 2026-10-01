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
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.curves.Brainpoolp256r1;
import com.ibm.mapper.model.curves.Brainpoolp384r1;
import com.ibm.mapper.model.curves.Brainpoolp512r1;
import com.ibm.mapper.model.curves.Secp192r1;
import com.ibm.mapper.model.curves.Secp224r1;
import com.ibm.mapper.model.curves.Secp256k1;
import com.ibm.mapper.model.curves.Secp256r1;
import com.ibm.mapper.model.curves.Secp384r1;
import com.ibm.mapper.model.curves.Secp521r1;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Maps the OpenSSL names of a named elliptic curve to the corresponding elliptic curve model
 * classes. A curve has a NIST name (e.g. {@code P-256}), an SEC 2 name (e.g. {@code secp256r1})
 * and, for some curves, an X9.62 name (e.g. {@code prime256v1}); OpenSSL accepts all of them as the
 * group of an EC key.
 */
public final class OpenSslCurveMapper implements IMapper {

    @Nonnull
    @Override
    public Optional<? extends EllipticCurve> parse(
            @Nullable String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }

        return switch (str.toUpperCase().trim()) {
            case "P-192", "P192", "SECP192R1", "PRIME192V1" ->
                    Optional.of(new Secp192r1(detectionLocation));
            case "P-224", "P224", "SECP224R1" -> Optional.of(new Secp224r1(detectionLocation));
            case "P-256", "P256", "SECP256R1", "PRIME256V1" ->
                    Optional.of(new Secp256r1(detectionLocation));
            case "P-384", "P384", "SECP384R1" -> Optional.of(new Secp384r1(detectionLocation));
            case "P-521", "P521", "SECP521R1" -> Optional.of(new Secp521r1(detectionLocation));
            case "SECP256K1" -> Optional.of(new Secp256k1(detectionLocation));
            case "BRAINPOOLP256R1" -> Optional.of(new Brainpoolp256r1(detectionLocation));
            case "BRAINPOOLP384R1" -> Optional.of(new Brainpoolp384r1(detectionLocation));
            case "BRAINPOOLP512R1" -> Optional.of(new Brainpoolp512r1(detectionLocation));
            default -> Optional.empty();
        };
    }
}
