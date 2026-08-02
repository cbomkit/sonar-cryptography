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
package com.ibm.plugin.rules.detection.openssl.cipher;

import com.ibm.engine.detection.ResolvedValue;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.factory.IValueFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.Optional;
import java.util.Set;
import javax.annotation.Nonnull;

/**
 * Resolves the algorithm-name argument of {@code EVP_CIPHER_fetch} to one of the provider-only
 * cipher modes this rule covers, whether the argument is a string literal at the call site or a
 * local variable/constant resolved to its string value (see {@link
 * com.ibm.engine.language.cxx.CxxDetectionEngine} value resolution), so a call such as {@code const
 * char* alg = "AES-128-SIV"; EVP_CIPHER_fetch(lib, alg, props);} is detected the same as the
 * literal form.
 *
 * <p>Only the modes with no {@code EVP_*} convenience function are covered here (see {@link
 * OpenSSLEvpCipherFetch} javadoc); other {@code EVP_CIPHER_fetch} argument values (e.g.
 * "AES-128-GCM", which has its own convenience function and its own detection rule) are out of
 * scope and correctly produce no finding from this rule.
 */
public final class OpenSSLCipherFetchFactory implements IValueFactory<AstNode> {

    private static final Set<String> KNOWN_MODES =
            Set.of(
                    "AES-128-SIV",
                    "AES-192-SIV",
                    "AES-256-SIV",
                    "AES-128-GCM-SIV",
                    "AES-192-GCM-SIV",
                    "AES-256-GCM-SIV",
                    "AES-128-CBC-CTS",
                    "AES-192-CBC-CTS",
                    "AES-256-CBC-CTS",
                    "AES-128-WRAP-INV",
                    "AES-192-WRAP-INV",
                    "AES-256-WRAP-INV",
                    "AES-128-WRAP-PAD-INV",
                    "AES-192-WRAP-PAD-INV",
                    "AES-256-WRAP-PAD-INV",
                    "AES-128-CBC-HMAC-SHA1",
                    "AES-128-CBC-HMAC-SHA256",
                    "AES-192-CBC-HMAC-SHA1",
                    "AES-192-CBC-HMAC-SHA256",
                    "AES-256-CBC-HMAC-SHA1",
                    "AES-256-CBC-HMAC-SHA256",
                    "AES-128-CBC-HMAC-SHA1-ETM",
                    "AES-192-CBC-HMAC-SHA1-ETM",
                    "AES-256-CBC-HMAC-SHA1-ETM",
                    "AES-128-CBC-HMAC-SHA256-ETM",
                    "AES-192-CBC-HMAC-SHA256-ETM",
                    "AES-256-CBC-HMAC-SHA256-ETM",
                    "AES-128-CBC-HMAC-SHA512-ETM",
                    "AES-192-CBC-HMAC-SHA512-ETM",
                    "AES-256-CBC-HMAC-SHA512-ETM",
                    "CAMELLIA-128-CBC-CTS",
                    "CAMELLIA-192-CBC-CTS",
                    "CAMELLIA-256-CBC-CTS");

    @Override
    @Nonnull
    public Optional<IValue<AstNode>> apply(@Nonnull ResolvedValue<Object, AstNode> resolvedValue) {
        final Object value = resolvedValue.value();
        if (value instanceof String str && KNOWN_MODES.contains(str)) {
            return Optional.of(new ValueAction<>(str, resolvedValue.tree()));
        }
        return Optional.empty();
    }
}
