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
package com.ibm.plugin.rules.detection.openssl.legacy;

import com.ibm.engine.rule.IDetectionRule;
import com.ibm.plugin.rules.detection.Memoize;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Stream;
import javax.annotation.Nonnull;

/**
 * Detection rules for OpenSSL legacy MAC (Message Authentication Code) APIs.
 *
 * <p>These rules detect MAC operations using the legacy (pre-EVP) APIs. These APIs are deprecated
 * but still widely used in existing codebases.
 *
 * <p>HMAC and CMAC each live in their own {@code OpenSSLLegacyMac<Family>} class; this class
 * aggregates both in {@link #rules()}. Poly1305 is intentionally excluded — its {@code
 * Poly1305_Init/Update/Final} symbols are OpenSSL-internal (declared in {@code
 * include/crypto/poly1305.h}, not {@code include/openssl/}). Public Poly1305 access in OpenSSL 3.x
 * is via {@code EVP_MAC_fetch(..., "POLY1305", ...)}, handled by {@link
 * com.ibm.plugin.rules.detection.openssl.mac.OpenSSLEvpMac}.
 */
public final class OpenSSLLegacyMac {

    private OpenSSLLegacyMac() {
        // private
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> buildRules() {
        return Stream.of(
                        OpenSSLLegacyMacHmac.rules().stream(),
                        OpenSSLLegacyMacCmac.rules().stream())
                .flatMap(i -> i)
                .toList();
    }

    private static final Supplier<List<IDetectionRule<AstNode>>> RULES =
            Memoize.of(OpenSSLLegacyMac::buildRules);

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return RULES.get();
    }
}
