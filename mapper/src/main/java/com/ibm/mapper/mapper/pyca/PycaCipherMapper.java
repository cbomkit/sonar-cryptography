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
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.Blowfish;
import com.ibm.mapper.model.algorithms.Camellia;
import com.ibm.mapper.model.algorithms.ChaCha20;
import com.ibm.mapper.model.algorithms.ChaCha20Poly1305;
import com.ibm.mapper.model.algorithms.DES;
import com.ibm.mapper.model.algorithms.Fernet;
import com.ibm.mapper.model.algorithms.IDEA;
import com.ibm.mapper.model.algorithms.RC2;
import com.ibm.mapper.model.algorithms.RC4;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.SEED;
import com.ibm.mapper.model.algorithms.SM4;
import com.ibm.mapper.model.algorithms.Salsa20;
import com.ibm.mapper.model.algorithms.TripleDES;
import com.ibm.mapper.model.algorithms.cast.CAST128;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public final class PycaCipherMapper implements IMapper {

    @Override
    public @Nonnull Optional<? extends INode> parse(
            @Nullable String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }

        return switch (str.toUpperCase().trim()) {
            case "AES" -> Optional.of(new AES(detectionLocation));
            case "AES128" -> Optional.of(new AES(128, detectionLocation));
            case "AES256" -> Optional.of(new AES(256, detectionLocation));
            case "CAMELLIA" -> Optional.of(new Camellia(detectionLocation));
            case "TRIPLEDES", "3DES" -> Optional.of(new TripleDES(detectionLocation));
            case "DES" -> Optional.of(new DES(detectionLocation));
            case "CAST5" -> Optional.of(new CAST128(detectionLocation));
            case "SEED" -> Optional.of(new SEED(detectionLocation));
            case "SM4" -> Optional.of(new SM4(detectionLocation));
            case "BLOWFISH" -> Optional.of(new Blowfish(detectionLocation));
            case "IDEA" -> Optional.of(new IDEA(detectionLocation));
            case "CHACHA20" -> Optional.of(new ChaCha20(detectionLocation));
            case "SALSA20" -> Optional.of(new Salsa20(detectionLocation));
            case "ARC4", "RC4" -> Optional.of(new RC4(detectionLocation));
            case "RC2" -> Optional.of(new RC2(detectionLocation));
            case "FERNET" -> Optional.of(new Fernet(detectionLocation));
            case "RSA" -> Optional.of(new RSA(detectionLocation));
            case "CHACHA20POLY1305", "CHACHA20_POLY1305" ->
                    Optional.of(new ChaCha20Poly1305(detectionLocation));
            default -> Optional.empty();
        };
    }
}
