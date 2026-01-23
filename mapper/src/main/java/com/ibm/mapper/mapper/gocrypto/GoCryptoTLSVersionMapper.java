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
import com.ibm.mapper.model.Version;
import com.ibm.mapper.utils.DetectionLocation;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Optional;

/**
 * Maps Go crypto/tls version constants to the corresponding TLS version strings.
 *
 * <p>Go's crypto/tls package defines the following version constants:
 *
 * <ul>
 *   <li>VersionSSL30 (0x0300) - SSLv3 (deprecated)
 *   <li>VersionTLS10 (0x0301) - TLS 1.0
 *   <li>VersionTLS11 (0x0302) - TLS 1.1
 *   <li>VersionTLS12 (0x0303) - TLS 1.2
 *   <li>VersionTLS13 (0x0304) - TLS 1.3
 * </ul>
 */
public final class GoCryptoTLSVersionMapper implements IMapper {

    @Nonnull
    @Override
    public Optional<Version> parse(
            @Nullable String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }

        return switch (str.trim()) {
            case "VersionSSL30" -> Optional.of(new Version("SSLv3", detectionLocation));
            case "VersionTLS10" -> Optional.of(new Version("1.0", detectionLocation));
            case "VersionTLS11" -> Optional.of(new Version("1.1", detectionLocation));
            case "VersionTLS12" -> Optional.of(new Version("1.2", detectionLocation));
            case "VersionTLS13" -> Optional.of(new Version("1.3", detectionLocation));
            default -> Optional.empty();
        };
    }
}
