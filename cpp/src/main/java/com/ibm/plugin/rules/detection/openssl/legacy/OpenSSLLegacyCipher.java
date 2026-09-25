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
 * Detection rules for OpenSSL legacy cipher APIs.
 *
 * <p>These rules detect direct cipher operations using the legacy (pre-EVP) APIs. These APIs are
 * deprecated but still widely used in existing codebases.
 *
 * <p>Per-family cipher rules live in their own {@code OpenSSLLegacyCipher<Family>} classes (AES,
 * DES/3DES, Blowfish, RC4, RC2, CAST, IDEA, Camellia, RC5, SEED); this class aggregates all of them
 * in {@link #rules()}.
 */
public final class OpenSSLLegacyCipher {

    private OpenSSLLegacyCipher() {
        // private
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> buildRules() {
        return Stream.of(
                        OpenSSLLegacyCipherAes.rules().stream(),
                        OpenSSLLegacyCipherDes.rules().stream(),
                        OpenSSLLegacyCipherBlowfish.rules().stream(),
                        OpenSSLLegacyCipherRc4.rules().stream(),
                        OpenSSLLegacyCipherRc2.rules().stream(),
                        OpenSSLLegacyCipherCast.rules().stream(),
                        OpenSSLLegacyCipherIdea.rules().stream(),
                        OpenSSLLegacyCipherCamellia.rules().stream(),
                        OpenSSLLegacyCipherRc5.rules().stream(),
                        OpenSSLLegacyCipherSeed.rules().stream())
                .flatMap(i -> i)
                .toList();
    }

    private static final Supplier<List<IDetectionRule<AstNode>>> RULES =
            Memoize.of(OpenSSLLegacyCipher::buildRules);

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return RULES.get();
    }
}
