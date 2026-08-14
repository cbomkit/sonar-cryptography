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
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.Blowfish;
import com.ibm.mapper.model.algorithms.Camellia;
import com.ibm.mapper.model.algorithms.ChaCha20;
import com.ibm.mapper.model.algorithms.Fernet;
import com.ibm.mapper.model.algorithms.IDEA;
import com.ibm.mapper.model.algorithms.KMAC;
import com.ibm.mapper.model.algorithms.MD2;
import com.ibm.mapper.model.algorithms.MD5;
import com.ibm.mapper.model.algorithms.Poly1305;
import com.ibm.mapper.model.algorithms.RC4;
import com.ibm.mapper.model.algorithms.RIPEMD;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.SEED;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.algorithms.SHA3;
import com.ibm.mapper.model.algorithms.SM3;
import com.ibm.mapper.model.algorithms.SM4;
import com.ibm.mapper.model.algorithms.TripleDES;
import com.ibm.mapper.model.algorithms.blake.BLAKE2b;
import com.ibm.mapper.model.algorithms.blake.BLAKE2s;
import com.ibm.mapper.model.algorithms.cast.CAST128;
import com.ibm.mapper.model.algorithms.shake.CSHAKE;
import com.ibm.mapper.model.algorithms.shake.SHAKE;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class PycaMacMapper implements IMapper {

    @Override
    public @Nonnull Optional<? extends INode> parse(
            @Nullable String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }

        return switch (str.toUpperCase().trim()) {
            case "AES" -> Optional.of(new AES(Mac.class, detectionLocation));
            case "AES128" -> Optional.of(new AES(Mac.class, new AES(128, detectionLocation)));
            case "AES256" -> Optional.of(new AES(Mac.class, new AES(256, detectionLocation)));
            case "CAMELLIA" ->
                    Optional.of(new Camellia(Mac.class, new Camellia(detectionLocation)));
            case "TRIPLEDES" ->
                    Optional.of(new TripleDES(Mac.class, new TripleDES(detectionLocation)));
            case "CAST5" -> Optional.of(new CAST128(Mac.class, new CAST128(detectionLocation)));
            case "SEED" -> Optional.of(new SEED(Mac.class, new SEED(detectionLocation)));
            case "SM4" -> Optional.of(new SM4(Mac.class, new SM4(detectionLocation)));
            case "BLOWFISH" ->
                    Optional.of(new Blowfish(Mac.class, new Blowfish(detectionLocation)));
            case "IDEA" -> Optional.of(new IDEA(Mac.class, new IDEA(detectionLocation)));
            case "CHACHA20" ->
                    Optional.of(new ChaCha20(Mac.class, new ChaCha20(detectionLocation)));
            case "ARC4" -> Optional.of(new RC4(Mac.class, new RC4(detectionLocation)));
            case "FERNET" -> Optional.of(new Fernet(Mac.class, new Fernet(detectionLocation)));
            case "RSA" -> Optional.of(new RSA(Mac.class, detectionLocation));
            case "SHA1" -> Optional.of(new SHA(Mac.class, new SHA(detectionLocation)));
            case "SHA512_224" ->
                    Optional.of(
                            new SHA2(
                                    Mac.class,
                                    new SHA2(
                                            224,
                                            new SHA2(512, detectionLocation),
                                            detectionLocation)));
            case "SHA512_256" ->
                    Optional.of(
                            new SHA2(
                                    Mac.class,
                                    new SHA2(
                                            256,
                                            new SHA2(512, detectionLocation),
                                            detectionLocation)));
            case "SHA224" -> Optional.of(new SHA2(Mac.class, new SHA2(224, detectionLocation)));
            case "SHA256" -> Optional.of(new SHA2(Mac.class, new SHA2(256, detectionLocation)));
            case "SHA384" -> Optional.of(new SHA2(Mac.class, new SHA2(384, detectionLocation)));
            case "SHA512" -> Optional.of(new SHA2(Mac.class, new SHA2(512, detectionLocation)));
            case "SHA3_224" -> Optional.of(new SHA3(Mac.class, new SHA3(224, detectionLocation)));
            case "SHA3_256" -> Optional.of(new SHA3(Mac.class, new SHA3(256, detectionLocation)));
            case "SHA3_384" -> Optional.of(new SHA3(Mac.class, new SHA3(384, detectionLocation)));
            case "SHA3_512" -> Optional.of(new SHA3(Mac.class, new SHA3(512, detectionLocation)));
            case "SHAKE128" -> Optional.of(new SHAKE(Mac.class, new SHAKE(128, detectionLocation)));
            case "SHAKE256" -> Optional.of(new SHAKE(Mac.class, new SHAKE(256, detectionLocation)));
            case "MD5" -> Optional.of(new MD5(Mac.class, detectionLocation));
            case "MD2" -> Optional.of(new MD2(Mac.class, detectionLocation));
            case "BLAKE2B" ->
                    Optional.of(new BLAKE2b(Mac.class, new BLAKE2b(false, detectionLocation)));
            case "BLAKE2S" ->
                    Optional.of(new BLAKE2s(Mac.class, new BLAKE2s(false, detectionLocation)));
            case "SM3" -> Optional.of(new SM3(Mac.class, new SM3(detectionLocation)));
            case "KMAC128" -> Optional.of(new KMAC(Mac.class, new KMAC(128, detectionLocation)));
            case "KMAC256" -> Optional.of(new KMAC(Mac.class, new KMAC(256, detectionLocation)));
            case "POLY1305" ->
                    Optional.of(new Poly1305(Mac.class, new Poly1305(detectionLocation)));
            case "RIPEMD160" ->
                    Optional.of(new RIPEMD(Mac.class, new RIPEMD(160, detectionLocation)));
            case "CSHAKE128" ->
                    Optional.of(new CSHAKE(Mac.class, new CSHAKE(128, detectionLocation)));
            case "CSHAKE256" ->
                    Optional.of(new CSHAKE(Mac.class, new CSHAKE(256, detectionLocation)));
            default -> Optional.empty();
        };
    }
}
