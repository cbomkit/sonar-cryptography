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
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Maps Go crypto/dsa ParameterSizes constants to KeyLength (the L value).
 *
 * <p>Go's crypto/dsa package defines these parameter sizes:
 *
 * <ul>
 *   <li>L1024N160 → KeyLength 1024
 *   <li>L2048N224 → KeyLength 2048
 *   <li>L2048N256 → KeyLength 2048
 *   <li>L3072N256 → KeyLength 3072
 * </ul>
 */
public final class GoCryptoDSAParameterMapper implements IMapper {

    @Nonnull
    @Override
    public Optional<? extends INode> parse(
            @Nullable String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }

        return switch (str.toUpperCase().trim()) {
            case "L1024N160" -> Optional.of(new KeyLength(1024, detectionLocation));
            case "L2048N224", "L2048N256" -> Optional.of(new KeyLength(2048, detectionLocation));
            case "L3072N256" -> Optional.of(new KeyLength(3072, detectionLocation));
            default -> Optional.empty();
        };
    }
}
