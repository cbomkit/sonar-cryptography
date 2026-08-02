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
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.Aria;
import com.ibm.mapper.model.algorithms.Camellia;
import com.ibm.mapper.model.algorithms.ChaCha20Poly1305;
import com.ibm.mapper.model.algorithms.DES;
import com.ibm.mapper.model.algorithms.IDEA;
import com.ibm.mapper.model.algorithms.RC2;
import com.ibm.mapper.model.algorithms.RC4;
import com.ibm.mapper.model.algorithms.SM4;
import com.ibm.mapper.model.algorithms.Skipjack;
import com.ibm.mapper.model.algorithms.TripleDES;
import com.ibm.mapper.model.algorithms.ascon.AsconAead128;
import com.ibm.mapper.model.algorithms.gost.GOST28147;
import com.ibm.mapper.model.algorithms.gost.GOSTR34122015;
import com.ibm.mapper.model.mode.CBC;
import com.ibm.mapper.model.mode.CCM;
import com.ibm.mapper.model.mode.CNT;
import com.ibm.mapper.model.mode.CTR;
import com.ibm.mapper.model.mode.GCM;
import com.ibm.mapper.model.mode.MGM;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public final class EncryptionAlgorithmMapper implements IMapper {

    @Nonnull
    @Override
    public Optional<? extends Algorithm> parse(
            @Nullable String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }

        return switch (str) {
            case "AES 128 CCM 8" ->
                    Optional.of(new AES(128, new CCM(8, detectionLocation), detectionLocation));
            case "AES 128 CCM" ->
                    Optional.of(new AES(128, new CCM(detectionLocation), detectionLocation));
            case "AES 128 GCM" ->
                    Optional.of(new AES(128, new GCM(detectionLocation), detectionLocation));
            case "AES 128 CBC" ->
                    Optional.of(new AES(128, new CBC(detectionLocation), detectionLocation));
            case "AES 256 CCM 8" ->
                    Optional.of(new AES(256, new CCM(8, detectionLocation), detectionLocation));
            case "AES 256 CCM" ->
                    Optional.of(new AES(256, new CCM(detectionLocation), detectionLocation));
            case "AES 256 GCM" ->
                    Optional.of(new AES(256, new GCM(detectionLocation), detectionLocation));
            case "AES 256 CBC" ->
                    Optional.of(new AES(256, new CBC(detectionLocation), detectionLocation));
            case "CHACHA20 POLY1305" -> Optional.of(new ChaCha20Poly1305(detectionLocation));
            case "RC4 40" -> Optional.of(new RC4(40, detectionLocation));
            case "RC4 128" -> Optional.of(new RC4(128, detectionLocation));
            case "RC2 CBC 40" ->
                    Optional.of(new RC2(40, new CBC(detectionLocation), detectionLocation));
            case "DES40 CBC", "DES CBC 40" -> Optional.of(new DES(40, detectionLocation));
            case "DES CBC" -> Optional.of(new DES(new CBC(detectionLocation), detectionLocation));
            case "3DES EDE CBC" ->
                    Optional.of(new TripleDES(new CBC(detectionLocation), detectionLocation));
            case "ARIA 128 CBC" ->
                    Optional.of(new Aria(128, new CBC(detectionLocation), detectionLocation));
            case "ARIA 128 GCM" ->
                    Optional.of(new Aria(128, new GCM(detectionLocation), detectionLocation));
            case "ARIA 256 CBC" ->
                    Optional.of(new Aria(256, new CBC(detectionLocation), detectionLocation));
            case "ARIA 256 GCM" ->
                    Optional.of(new Aria(256, new GCM(detectionLocation), detectionLocation));
            case "CAMELLIA 128 CBC" ->
                    Optional.of(new Camellia(128, new CBC(detectionLocation), detectionLocation));
            case "CAMELLIA 128 GCM" ->
                    Optional.of(new Camellia(128, new GCM(detectionLocation), detectionLocation));
            case "CAMELLIA 256 CBC" ->
                    Optional.of(new Camellia(256, new CBC(detectionLocation), detectionLocation));
            case "CAMELLIA 256 GCM" ->
                    Optional.of(new Camellia(256, new GCM(detectionLocation), detectionLocation));
            case "SEED CBC" ->
                    Optional.of(new Skipjack(new CBC(detectionLocation), detectionLocation));
            case "28147 CNT" ->
                    Optional.of(new GOST28147(new CNT(detectionLocation), detectionLocation));
            case "MAGMA CTR" ->
                    Optional.of(new GOST28147(new CTR(detectionLocation), detectionLocation));
            case "MAGMA MGM L", "MAGMA MGM S" ->
                    Optional.of(new GOST28147(new MGM(detectionLocation), detectionLocation));
            case "KUZNYECHIK CTR" ->
                    Optional.of(new GOSTR34122015(new CTR(detectionLocation), detectionLocation));
            case "KUZNYECHIK MGM L", "KUZNYECHIK MGM S" ->
                    Optional.of(new GOSTR34122015(new MGM(detectionLocation), detectionLocation));
            case "IDEA CBC" -> Optional.of(new IDEA(new CBC(detectionLocation), detectionLocation));
            case "SM4 CCM" -> Optional.of(new SM4(new CCM(detectionLocation), detectionLocation));
            case "SM4 GCM" -> Optional.of(new SM4(new GCM(detectionLocation), detectionLocation));
            case "ASCONAEAD128" -> Optional.of(new AsconAead128(detectionLocation));
            default -> Optional.empty();
        };
    }
}
