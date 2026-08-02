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
package com.ibm.plugin.rules.detection.openssl.keygen;

import com.ibm.engine.detection.ResolvedValue;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.factory.IValueFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Resolves a numeric key-length argument (e.g. {@code EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits)},
 * {@code EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, bits)}) to {@code "<prefix>-<bits>"} for whatever
 * value the call actually carries, rather than a fixed set of guessed lengths. A non-numeric
 * argument resolves to nothing.
 */
public final class OpenSSLKeygenBitsFactory implements IValueFactory<AstNode> {

    @Nonnull private final String prefix;

    public OpenSSLKeygenBitsFactory(@Nonnull String prefix) {
        this.prefix = prefix;
    }

    @Override
    @Nonnull
    public Optional<IValue<AstNode>> apply(@Nonnull ResolvedValue<Object, AstNode> resolvedValue) {
        if (!(resolvedValue.value() instanceof Number bits)) {
            return Optional.empty();
        }
        return Optional.of(new ValueAction<>(prefix + "-" + bits.intValue(), resolvedValue.tree()));
    }
}
