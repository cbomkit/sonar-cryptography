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
import com.ibm.engine.model.CipherAction;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.factory.IValueFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Resolves the {@code enc} argument of {@code EVP_CipherInit} to the operation the cipher is
 * initialized for: 1 encrypts and 0 decrypts. Any other value (-1) keeps the operation of an
 * earlier initialization and yields no operation.
 */
public final class OpenSSLCipherOperationFactory implements IValueFactory<AstNode> {

    @Override
    @Nonnull
    public Optional<IValue<AstNode>> apply(@Nonnull ResolvedValue<Object, AstNode> resolvedValue) {
        if (!(resolvedValue.value() instanceof Number enc)) {
            return Optional.empty();
        }
        return switch (enc.intValue()) {
            case 1 ->
                    Optional.of(
                            new CipherAction<>(CipherAction.Action.ENCRYPT, resolvedValue.tree()));
            case 0 ->
                    Optional.of(
                            new CipherAction<>(CipherAction.Action.DECRYPT, resolvedValue.tree()));
            default -> Optional.empty();
        };
    }
}
