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

import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.CipherSuite;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.model.context.ProtocolContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.mapper.IMapper;
import com.ibm.mapper.mapper.ssl.CipherSuiteMapper;
import com.ibm.mapper.mapper.ssl.OpenSslGroupMapper;
import com.ibm.mapper.mapper.ssl.OpenSslSignatureMapper;
import com.ibm.mapper.mapper.ssl.SSLVersionMapper;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Protocol;
import com.ibm.mapper.model.Unknown;
import com.ibm.mapper.model.Version;
import com.ibm.mapper.model.collections.AssetCollection;
import com.ibm.mapper.model.protocol.TLS;
import com.ibm.mapper.utils.DetectionLocation;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Translates OpenSSL libssl protocol contexts to CBOM model nodes.
 *
 * <p>Handles SSL/TLS protocol detection including version strings (TLS 1.2, TLS 1.3, DTLS, QUIC,
 * etc.) and cipher suite configurations.
 */
public final class CxxProtocolContextTranslator implements IContextTranslation<AstNode> {

    @Nonnull
    @Override
    public Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<AstNode> value,
            @Nonnull IDetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {
        if (!bundleIdentifier.getIdentifier().equals("OpenSSL")) {
            return Optional.empty();
        }

        final ProtocolContext.Kind kind = ((ProtocolContext) detectionContext).kind();

        if (value instanceof com.ibm.engine.model.Protocol<AstNode> protocol) {
            return switch (kind) {
                case TLS ->
                        Optional.of(protocol)
                                .map(
                                        p -> {
                                            final SSLVersionMapper sslVersionMapper =
                                                    new SSLVersionMapper();
                                            return sslVersionMapper
                                                    .parse(p.asString(), detectionLocation)
                                                    .map(TLS::new)
                                                    .orElse(new TLS(detectionLocation));
                                        });
                default ->
                        Optional.of(protocol)
                                .map(p -> new Protocol(p.asString(), detectionLocation));
            };
        } else if (value instanceof CipherSuite<AstNode> cipherSuite) {
            return switch (kind) {
                case TLS ->
                        new CipherSuiteMapper()
                                .parse(cipherSuite.get(), detectionLocation)
                                .map(n -> n);
                default ->
                        Optional.of(cipherSuite)
                                .map(
                                        suite ->
                                                new com.ibm.mapper.model.CipherSuite(
                                                        suite.asString(), detectionLocation));
            };
        } else if (value instanceof Algorithm<AstNode> algorithm) {
            return switch (kind) {
                case TLS_SIGNATURE_ALGORITHMS ->
                        translateList(
                                algorithm.asString(),
                                new OpenSslSignatureMapper(),
                                detectionLocation);
                case TLS_GROUPS ->
                        translateList(
                                algorithm.asString(), new OpenSslGroupMapper(), detectionLocation);
                default -> Optional.of(new Protocol(algorithm.asString(), detectionLocation));
            };
        } else if (value instanceof ValueAction<AstNode> valueAction) {
            final String stringValue = valueAction.asString();
            if (kind == ProtocolContext.Kind.TLS
                    && stringValue.regionMatches(true, 0, "tls", 0, 3)) {
                // TLSv* strings: extract the version number and emit a typed TLS node.
                // SSLv3, DTLS* and config strings (TLS-CIPHER-CONFIG etc.) share
                // ProtocolContext.Kind.TLS but do not start with "tls" — they fall through
                // to the generic Protocol path below.
                final SSLVersionMapper sslVersionMapper = new SSLVersionMapper();
                final Optional<Version> parsedVersion =
                        sslVersionMapper.parse(stringValue, detectionLocation);
                if (parsedVersion.isPresent()) {
                    return Optional.of(new TLS(parsedVersion.get()));
                }
            }
            return Optional.of(new Protocol(stringValue, detectionLocation));
        }

        return Optional.of(new Unknown(detectionLocation));
    }

    /**
     * Splits a colon-separated OpenSSL algorithm list (e.g. {@code "MLKEM768:X25519"}) and maps
     * each entry with the given per-library mapper. Unrecognized names are skipped entirely rather
     * than kept as a raw placeholder. The result is a single {@link AssetCollection} node holding
     * only the recognized entries.
     */
    @Nonnull
    private static Optional<INode> translateList(
            @Nonnull String list,
            @Nonnull IMapper mapper,
            @Nonnull DetectionLocation detectionLocation) {
        final List<INode> nodes = new ArrayList<>();
        for (String rawName : list.split(":")) {
            final String name = rawName.trim();
            if (name.isEmpty()) {
                continue;
            }
            mapper.parse(name, detectionLocation).map(n -> (INode) n).ifPresent(nodes::add);
        }
        if (nodes.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(new AssetCollection(nodes));
    }
}
