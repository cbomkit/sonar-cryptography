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
package com.ibm.plugin.translation.translator.contexts;

import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.DetectionContext;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.mapper.openssl.OpenSslKemMapper;
import com.ibm.mapper.mapper.openssl.OpenSslKeyAgreementMapper;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.utils.DetectionLocation;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Translator for C++ key agreement detection contexts.
 *
 * <p>This translator handles the translation of key agreement-related detection values (Diffie-
 * Hellman, ECDH, X25519/X448, ML-KEM, SM2) to the mapper model nodes. Values detected with the
 * context kind {@code KEM} are key encapsulation mechanism names, and values with the kind {@code
 * HPKE} are HPKE suites.
 */
public final class CxxKeyAgreementContextTranslator implements IContextTranslation<AstNode> {

    @Override
    public @Nonnull Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<AstNode> value,
            @Nonnull IDetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {

        if (value instanceof ValueAction<AstNode>
                || value instanceof com.ibm.engine.model.Algorithm<AstNode>) {
            final String kind =
                    detectionContext instanceof DetectionContext context
                            ? context.get("kind").orElse("")
                            : "";
            return switch (kind) {
                case "KEM" ->
                        new OpenSslKemMapper()
                                .parse(value.asString(), detectionLocation)
                                .map(node -> node);
                case "HPKE" ->
                        new OpenSslKemMapper()
                                .parseHpkeSuite(value.asString(), detectionLocation)
                                .map(node -> node);
                default ->
                        new OpenSslKeyAgreementMapper()
                                .parse(value.asString(), detectionLocation)
                                .map(node -> node);
            };
        }

        return Optional.empty();
    }
}
