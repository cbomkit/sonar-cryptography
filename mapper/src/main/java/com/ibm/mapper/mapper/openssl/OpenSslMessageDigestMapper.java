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
import com.ibm.mapper.mapper.jca.JcaMessageDigestMapper;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.algorithms.MD4;
import com.ibm.mapper.model.algorithms.MD5SHA1;
import com.ibm.mapper.model.algorithms.MDC2;
import com.ibm.mapper.model.algorithms.RIPEMD;
import com.ibm.mapper.model.algorithms.SM3;
import com.ibm.mapper.model.algorithms.Whirlpool;
import com.ibm.mapper.model.algorithms.blake.BLAKE2b;
import com.ibm.mapper.model.algorithms.blake.BLAKE2s;
import com.ibm.mapper.model.algorithms.shake.SHAKE;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Maps the OpenSSL digest names (the names accepted by {@code EVP_MD_fetch} and {@code
 * EVP_get_digestbyname}, and the names the digest detection rules give the {@code EVP_*} digest
 * functions and the legacy digest functions) to the model. The names shared with the JCA are mapped
 * by {@link JcaMessageDigestMapper}.
 */
public class OpenSslMessageDigestMapper implements IMapper {

    @Nonnull
    @Override
    public Optional<? extends MessageDigest> parse(
            @Nullable final String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }
        final Optional<MessageDigest> jcaDigest =
                new JcaMessageDigestMapper().parse(str, detectionLocation);
        if (jcaDigest.isPresent()) {
            return jcaDigest;
        }
        return switch (str.toUpperCase().trim()) {
            case "MD4" -> Optional.of(new MD4(detectionLocation));
            case "MDC2" -> Optional.of(new MDC2(detectionLocation));
            case "MD5-SHA1" -> Optional.of(new MD5SHA1(detectionLocation));
            case "SHAKE128" -> Optional.of(new SHAKE(128, detectionLocation));
            case "SHAKE256" -> Optional.of(new SHAKE(256, detectionLocation));
            case "RIPEMD160" -> Optional.of(new RIPEMD(160, detectionLocation));
            case "WHIRLPOOL" -> Optional.of(new Whirlpool(detectionLocation));
            case "BLAKE2B-512" -> Optional.of(new BLAKE2b(512, false, detectionLocation));
            case "BLAKE2S-256" -> Optional.of(new BLAKE2s(256, false, detectionLocation));
            case "SM3" -> Optional.of(new SM3(detectionLocation));
            // EVP_md_null: no digest
            default -> Optional.empty();
        };
    }
}
