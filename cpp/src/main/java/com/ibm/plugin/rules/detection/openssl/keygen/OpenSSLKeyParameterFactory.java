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
import com.ibm.engine.model.Curve;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.Size;
import com.ibm.engine.model.factory.IValueFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Resolves a key generation parameter: a positive key size in bits (e.g. the bits of {@code
 * EVP_PKEY_Q_keygen(NULL, NULL, "RSA", 2048)}) or a group name (e.g. {@code
 * EVP_PKEY_CTX_set_group_name(ctx, "P-256")}). A finite-field group name ({@code "ffdhe2048"})
 * resolves to the size of its prime; any other group name resolves to a {@link Curve} of that name
 * (e.g. {@code "EC-P-256"}), which the key mapper recognizes by any of its OpenSSL names.
 */
public final class OpenSSLKeyParameterFactory implements IValueFactory<AstNode> {

    private static final String FFDHE = "FFDHE";

    /** The prefix of a curve, by which the key mapper tells it from other algorithm names. */
    private static final String EC_CURVE_PREFIX = "EC-";

    @Override
    @Nonnull
    public Optional<IValue<AstNode>> apply(@Nonnull ResolvedValue<Object, AstNode> resolvedValue) {
        final Object value = resolvedValue.value();
        if (value instanceof Number) {
            // only a positive integer is a key size
            return value instanceof Integer bits && bits > 0
                    ? Optional.of(new KeySize<>(bits, Size.UnitType.BIT, resolvedValue.tree()))
                    : Optional.empty();
        }
        if (!(value instanceof String name)) {
            return Optional.empty();
        }
        final String group = name.toUpperCase().trim();
        if (group.startsWith(FFDHE)) {
            try {
                return Optional.of(
                        new KeySize<>(
                                Integer.parseInt(group.substring(FFDHE.length())),
                                Size.UnitType.BIT,
                                resolvedValue.tree()));
            } catch (NumberFormatException e) {
                return Optional.empty();
            }
        }
        return Optional.of(new Curve<>(EC_CURVE_PREFIX + name.trim(), resolvedValue.tree()));
    }
}
