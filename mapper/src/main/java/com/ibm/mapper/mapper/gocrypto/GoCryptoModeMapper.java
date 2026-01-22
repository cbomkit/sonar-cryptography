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
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.mode.CBC;
import com.ibm.mapper.model.mode.CFB;
import com.ibm.mapper.model.mode.CTR;
import com.ibm.mapper.model.mode.GCM;
import com.ibm.mapper.model.mode.OFB;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Maps Go crypto/cipher mode names to the corresponding mode model classes.
 *
 * <p>Go's crypto/cipher package provides the following block cipher modes:
 *
 * <ul>
 *   <li>GCM - Galois/Counter Mode (AEAD)
 *   <li>CBC - Cipher Block Chaining
 *   <li>CFB - Cipher Feedback
 *   <li>CTR - Counter Mode
 *   <li>OFB - Output Feedback
 * </ul>
 */
public final class GoCryptoModeMapper implements IMapper {

    @Nonnull
    @Override
    public Optional<? extends Mode> parse(
            @Nullable String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }

        return switch (str.toUpperCase().trim()) {
            case "GCM" -> Optional.of(new GCM(detectionLocation));
            case "CBC" -> Optional.of(new CBC(detectionLocation));
            case "CFB" -> Optional.of(new CFB(detectionLocation));
            case "CTR" -> Optional.of(new CTR(detectionLocation));
            case "OFB" -> Optional.of(new OFB(detectionLocation));
            default -> Optional.empty();
        };
    }
}
