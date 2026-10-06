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
package com.ibm.plugin.rules.detection.openssl.mac;

import com.ibm.engine.detection.ResolvedValue;
import com.ibm.engine.model.AlgorithmParameter;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.factory.IValueFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Resolves the algorithm a MAC is computed with, the {@code subalg} argument of {@code EVP_Q_mac}:
 * the name of the digest of an HMAC or of the cipher of a CMAC or GMAC, e.g. {@code "SHA256"}. The
 * name is kept as an algorithm parameter of the MAC, which the MAC translation maps to the digest
 * or the cipher it names.
 */
public final class OpenSSLMacSubAlgorithmFactory implements IValueFactory<AstNode> {

    @Nonnull
    @Override
    public Optional<IValue<AstNode>> apply(@Nonnull ResolvedValue<Object, AstNode> resolvedValue) {
        if (!(resolvedValue.value() instanceof String name) || name.isBlank()) {
            return Optional.empty();
        }
        return Optional.of(
                new AlgorithmParameter<>(
                        name.trim(), AlgorithmParameter.Kind.ANY, resolvedValue.tree()));
    }
}
