/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2026 PQCA
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
import com.ibm.engine.model.Padding;
import com.ibm.engine.model.factory.IValueFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Resolves the {@code pad} argument of {@code EVP_CIPHER_CTX_set_padding(ctx, pad)}. A non-zero
 * value enables the standard block padding of OpenSSL, PKCS#7; zero disables padding, which, as the
 * JCA {@code NoPadding}, is no padding to report.
 */
public final class OpenSSLCipherPaddingFactory implements IValueFactory<AstNode> {

    private static final String STANDARD_BLOCK_PADDING = "PKCS7";

    @Override
    @Nonnull
    public Optional<IValue<AstNode>> apply(@Nonnull ResolvedValue<Object, AstNode> resolvedValue) {
        if (resolvedValue.value() instanceof Number pad && pad.longValue() != 0) {
            return Optional.of(new Padding<>(STANDARD_BLOCK_PADDING, resolvedValue.tree()));
        }
        return Optional.empty();
    }
}
