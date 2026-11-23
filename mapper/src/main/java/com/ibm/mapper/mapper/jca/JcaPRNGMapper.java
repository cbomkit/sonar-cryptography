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
package com.ibm.mapper.mapper.jca;

import com.ibm.mapper.mapper.IMapper;
import com.ibm.mapper.model.PseudorandomNumberGenerator;
import com.ibm.mapper.model.algorithms.PRNG;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class JcaPRNGMapper implements IMapper {

    @Nonnull
    @Override
    public Optional<? extends PseudorandomNumberGenerator> parse(
            @Nullable String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }

        if (str.toUpperCase().contains("SHA1")) {
            return Optional.of(
                    new SHA(PseudorandomNumberGenerator.class, new SHA(detectionLocation)));
        }

        return switch (str.toUpperCase().trim()) {
            case "NATIVEPRNG",
                    "DRBG",
                    "NATIVEPRNGBLOCKING",
                    "NATIVEPRNGNONBLOCKING",
                    "WINDOWS-PRNG" ->
                    Optional.of(new PRNG(detectionLocation));
            default -> Optional.empty();
        };
    }
}
