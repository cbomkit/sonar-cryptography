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

import com.ibm.engine.model.CipherSuite;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.Protocol;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.model.context.ProtocolContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.mapper.gocrypto.GoCryptoTLSVersionMapper;
import com.ibm.mapper.mapper.ssl.CipherSuiteMapper;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.collections.CipherSuiteCollection;
import com.ibm.mapper.model.protocol.TLS;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.sonar.plugins.go.api.Tree;

public final class GoProtocolContextTranslator implements IContextTranslation<Tree> {

    @Nonnull
    @Override
    public Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<Tree> value,
            @Nonnull IDetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {
        if (value instanceof ValueAction<Tree> valueAction) {
            return switch (valueAction.asString()) {
                case "TLS" -> Optional.of(new TLS(detectionLocation));
                default -> Optional.empty();
            };
        } else if (value instanceof Protocol<Tree> protocol) {
            final GoCryptoTLSVersionMapper versionMapper = new GoCryptoTLSVersionMapper();
            return versionMapper.parse(protocol.asString(), detectionLocation).map(TLS::new);
        } else if (value instanceof CipherSuite<Tree> cipherSuite
                && detectionContext instanceof ProtocolContext protocolContext) {
            return switch (protocolContext.kind()) {
                case TLS ->
                        new CipherSuiteMapper()
                                .parse(cipherSuite.get(), detectionLocation)
                                .map(com.ibm.mapper.model.CipherSuite.class::cast)
                                .map(cs -> new CipherSuiteCollection(List.of(cs)));
                default -> Optional.empty();
            };
        }

        return Optional.empty();
    }
}
