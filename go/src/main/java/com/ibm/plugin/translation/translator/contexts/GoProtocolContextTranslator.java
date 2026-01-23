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
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.model.context.ProtocolContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.mapper.ssl.CipherSuiteMapper;
import com.ibm.mapper.mapper.ssl.SSLVersionMapper;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.protocol.TLS;
import com.ibm.mapper.utils.DetectionLocation;
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

        final ProtocolContext.Kind kind = ((ProtocolContext) detectionContext).kind();

        if (value instanceof ValueAction<Tree>) {
            String valueStr = value.asString();
            return switch (kind) {
                case TLS -> {
                    // Try to parse as a cipher suite name (e.g.
                    // "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
                    if (valueStr.startsWith("TLS_")) {
                        CipherSuiteMapper cipherSuiteMapper = new CipherSuiteMapper();
                        Optional<INode> cipherSuiteResult =
                                cipherSuiteMapper.parse(valueStr, detectionLocation).map(n -> n);
                        if (cipherSuiteResult.isPresent()) {
                            yield cipherSuiteResult;
                        }
                    }
                    // Try to parse as a version string (e.g. "TLSv1.2", "TLSv1.3", "SSLv3")
                    SSLVersionMapper versionMapper = new SSLVersionMapper();
                    Optional<INode> versionResult =
                            versionMapper
                                    .parse(valueStr, detectionLocation)
                                    .map(version -> (INode) new TLS(version));
                    if (versionResult.isPresent()) {
                        yield versionResult;
                    }
                    // Default: plain TLS protocol detection
                    yield Optional.of(new TLS(detectionLocation));
                }
                default -> Optional.empty();
            };
        } else if (value instanceof CipherSuite<Tree> cipherSuite) {
            return switch (kind) {
                case TLS ->
                        new CipherSuiteMapper()
                                .parse(cipherSuite.get(), detectionLocation)
                                .map(n -> n);
                default ->
                        Optional.of(
                                new com.ibm.mapper.model.CipherSuite(
                                        cipherSuite.asString(), detectionLocation));
            };
        }

        return Optional.empty();
    }
}
