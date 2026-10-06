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
package com.ibm.mapper.mapper.ssl;

import com.ibm.mapper.mapper.IMapper;
import com.ibm.mapper.mapper.ssl.json.JsonCipherSuite;
import com.ibm.mapper.mapper.ssl.json.JsonCipherSuites;
import com.ibm.mapper.model.CipherSuite;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Identifier;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.collections.AssetCollection;
import com.ibm.mapper.model.collections.IdentifierCollection;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public final class CipherSuiteMapper implements IMapper {

    @Nonnull
    @Override
    public Optional<? extends INode> parse(
            @Nullable String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }

        Optional<JsonCipherSuite> possibleJsonCipherSuite = findCipherSuite(str);
        if (possibleJsonCipherSuite.isEmpty()) {
            // return a 'simple' cipher object
            return Optional.of(new CipherSuite(str, detectionLocation));
        }
        final JsonCipherSuite jsonCipherSuite = possibleJsonCipherSuite.get();

        List<INode> assets = new ArrayList<>();
        // key agreement
        jsonCipherSuite
                .getKexAlgorithm()
                .flatMap(
                        algoStr -> {
                            final KeyExchangeAlgorithmMapper keyExchangeAlgorithmMapper =
                                    new KeyExchangeAlgorithmMapper();
                            return keyExchangeAlgorithmMapper.parse(algoStr, detectionLocation);
                        })
                .ifPresent(assets::add);
        // encryption algorithm
        jsonCipherSuite
                .getEncAlgorithm()
                .flatMap(
                        algoStr -> {
                            final EncryptionAlgorithmMapper encryptionAlgorithmMapper =
                                    new EncryptionAlgorithmMapper();
                            return encryptionAlgorithmMapper.parse(algoStr, detectionLocation);
                        })
                .ifPresent(assets::add);
        // hash algorithm
        final Optional<MessageDigest> hash =
                jsonCipherSuite
                        .getHashAlgorithm()
                        .flatMap(
                                algoStr -> {
                                    final HashAlgorithmMapper hashAlgorithmMapper =
                                            new HashAlgorithmMapper();
                                    return hashAlgorithmMapper.parse(algoStr, detectionLocation);
                                });
        // authentication agreement
        jsonCipherSuite
                .getAuthAlgorithm()
                .flatMap(
                        algoStr -> {
                            final AuthenticationAlgorithmMapper authenticationAlgorithmMapper =
                                    new AuthenticationAlgorithmMapper();
                            return authenticationAlgorithmMapper.parse(algoStr, detectionLocation);
                        })
                .ifPresentOrElse(
                        sign -> {
                            hash.ifPresent(sign::put);
                            assets.add(sign);
                        },
                        () -> hash.ifPresent(assets::add));

        final CipherSuite cipherSuite =
                new CipherSuite(
                        jsonCipherSuite.getIanaName(),
                        new AssetCollection(assets),
                        detectionLocation);
        jsonCipherSuite
                .getIdentifiers()
                .flatMap(
                        ids -> {
                            final List<Identifier> identifiers =
                                    Arrays.stream(ids)
                                            .map(idStr -> new Identifier(idStr, detectionLocation))
                                            .toList();
                            return Optional.of(identifiers.stream());
                        })
                .map(identifierStream -> new IdentifierCollection(identifierStream.toList()))
                .ifPresent(cipherSuite::put);

        return Optional.of(cipherSuite);
    }

    @Nonnull
    public static Optional<JsonCipherSuite> findCipherSuite(@Nonnull final String identifier) {
        return Optional.ofNullable(JsonCipherSuites.CIPHER_SUITES.get(identifier))
                .or(
                        () -> {
                            Collection<JsonCipherSuite> suites =
                                    JsonCipherSuites.CIPHER_SUITES.values();
                            for (JsonCipherSuite suite : suites) {
                                if (suite.getGnutlsName().isPresent()
                                        && suite.getGnutlsName().get().equals(identifier)) {
                                    return Optional.of(suite);
                                }
                                if (suite.getOpensslName().isPresent()
                                        && suite.getOpensslName().get().equals(identifier)) {
                                    return Optional.of(suite);
                                }
                            }
                            return OpenSslCipherSuiteNames.ianaName(identifier)
                                    .map(JsonCipherSuites.CIPHER_SUITES::get);
                        });
    }
}
