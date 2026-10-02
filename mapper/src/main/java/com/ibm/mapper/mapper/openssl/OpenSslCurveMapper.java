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

/**
 * Maps the OpenSSL names of a named elliptic curve to the corresponding elliptic curve model
 * classes. A curve has an SEC 2 short name (e.g. {@code secp256r1}), for some curves an X9.62 name
 * (e.g. {@code prime256v1}) and a NIST name (e.g. {@code P-256}, {@code K-283}, {@code B-283});
 * OpenSSL accepts all of them as the group of an EC key (obj_mac.h, crypto/evp/ec_support.c).
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
            case "P-192", "SECP192R1", "PRIME192V1" ->
                    Optional.of(new Secp192r1(detectionLocation));
            case "P-224", "SECP224R1" -> Optional.of(new Secp224r1(detectionLocation));
            case "P-256", "SECP256R1", "PRIME256V1" ->
                    Optional.of(new Secp256r1(detectionLocation));
            case "P-384", "SECP384R1" -> Optional.of(new Secp384r1(detectionLocation));
            case "P-521", "SECP521R1" -> Optional.of(new Secp521r1(detectionLocation));
            case "SECP256K1" -> Optional.of(new Secp256k1(detectionLocation));
            case "BRAINPOOLP256R1" -> Optional.of(new Brainpoolp256r1(detectionLocation));
            case "BRAINPOOLP384R1" -> Optional.of(new Brainpoolp384r1(detectionLocation));
            case "BRAINPOOLP512R1" -> Optional.of(new Brainpoolp512r1(detectionLocation));
            case "K-163", "SECT163K1" -> Optional.of(new Sect163k1(detectionLocation));
            case "B-163", "SECT163R2" -> Optional.of(new Sect163r2(detectionLocation));
            case "K-233", "SECT233K1" -> Optional.of(new Sect233k1(detectionLocation));
            case "B-233", "SECT233R1" -> Optional.of(new Sect233r1(detectionLocation));
            case "K-283", "SECT283K1" -> Optional.of(new Sect283k1(detectionLocation));
            case "B-283", "SECT283R1" -> Optional.of(new Sect283r1(detectionLocation));
            case "K-409", "SECT409K1" -> Optional.of(new Sect409k1(detectionLocation));
            case "B-409", "SECT409R1" -> Optional.of(new Sect409r1(detectionLocation));
            case "K-571", "SECT571K1" -> Optional.of(new Sect571k1(detectionLocation));
            case "B-571", "SECT571R1" -> Optional.of(new Sect571r1(detectionLocation));
            default -> Optional.empty();
        };
    }
}
