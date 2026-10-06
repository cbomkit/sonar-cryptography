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
package com.ibm.plugin.rules.detection.openssl;

import com.ibm.engine.detection.ResolvedValue;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.factory.IValueFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * The value of a size argument, e.g. the key length in bits of {@code
 * EVP_PKEY_CTX_set_rsa_keygen_bits} or in bytes of {@code PKCS5_PBKDF2_HMAC}. OpenSSL takes sizes
 * as integers, so only a positive integer is a size: a name whose value is not known, such as a
 * macro defined in a header that is not analyzed, and a value that is not positive give no size.
 */
public final class OpenSSLSizeFactory implements IValueFactory<AstNode> {

    @Nonnull private final IValueFactory<AstNode> sizeFactory;

    /**
     * @param sizeFactory the factory creating the size from a positive integer, e.g. a key size
     *     factory interpreting it as bits or bytes
     */
    public OpenSSLSizeFactory(@Nonnull IValueFactory<AstNode> sizeFactory) {
        this.sizeFactory = sizeFactory;
    }

    @Override
    @Nonnull
    public Optional<IValue<AstNode>> apply(@Nonnull ResolvedValue<Object, AstNode> resolvedValue) {
        if (resolvedValue.value() instanceof Integer size && size > 0) {
            return sizeFactory.apply(resolvedValue);
        }
        return Optional.empty();
    }
}
