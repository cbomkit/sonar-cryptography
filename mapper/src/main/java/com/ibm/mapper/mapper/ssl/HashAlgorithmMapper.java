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
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.algorithms.MD5;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.algorithms.SM3;
import com.ibm.mapper.model.algorithms.ascon.AsconHash;
import com.ibm.mapper.model.algorithms.gost.GOSTR341112;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public final class HashAlgorithmMapper implements IMapper {

    @Nonnull
    @Override
    public Optional<MessageDigest> parse(
            @Nullable String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }

        return switch (str) {
            case "MD5" -> Optional.of(new MD5(detectionLocation));
            case "SHA" -> Optional.of(new SHA(detectionLocation));
            case "SHA256" -> Optional.of(new SHA2(256, detectionLocation));
            case "SHA384" -> Optional.of(new SHA2(384, detectionLocation));
            case "SM3" -> Optional.of(new SM3(detectionLocation));
            case "GOSTR341112" -> Optional.of(new GOSTR341112(detectionLocation));
            case "ASCONHASH256" -> Optional.of(new AsconHash(detectionLocation));
            default -> Optional.empty();
        };
    }
}
