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
import com.ibm.mapper.model.IPrimitive;
import com.ibm.mapper.model.Identifier;
import com.ibm.mapper.model.Protocol;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.TagLength;
import com.ibm.mapper.model.Unknown;
import com.ibm.mapper.model.Version;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.Aria;
import com.ibm.mapper.model.algorithms.HMAC;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.model.collections.AssetCollection;
import com.ibm.mapper.model.collections.CipherSuiteCollection;
import com.ibm.mapper.model.collections.IdentifierCollection;
import com.ibm.mapper.model.mode.CTR;
import com.ibm.mapper.model.mode.GCM;
import com.ibm.mapper.model.protocol.TLS;
import com.ibm.mapper.utils.DetectionLocation;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
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
                                                    .<INode>map(
                                                            version ->
                                                                    new TLS(p.asString(), version))
                                                    .orElse(new TLS(detectionLocation));
                                        });
                default ->
                        Optional.of(protocol)
                                .map(p -> new Protocol(p.asString(), detectionLocation));
            };
        } else if (value instanceof CipherSuite<AstNode> cipherSuite) {
            return switch (kind) {
                case TLS -> translateCipherString(cipherSuite.get(), detectionLocation);
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
                                Signature.class,
                                detectionLocation);
                // a group is a key agreement or a key encapsulation mechanism
                case TLS_GROUPS ->
                        translateList(
                                algorithm.asString(),
                                new OpenSslGroupMapper(),
                                Unknown.class,
                                detectionLocation);
                case SRTP -> translateSrtpProfiles(algorithm.asString(), detectionLocation);
                default -> Optional.of(new Protocol(algorithm.asString(), detectionLocation));
            };
        } else if (value instanceof ValueAction<AstNode> valueAction) {
            final String stringValue = valueAction.asString();
            if (kind == ProtocolContext.Kind.TLS) {
                // TLS_method() and its client and server forms negotiate the version
                if (stringValue.equals("TLS")) {
                    return Optional.of(new TLS(detectionLocation));
                }
                final SSLVersionMapper sslVersionMapper = new SSLVersionMapper();
                final Optional<Version> parsedVersion =
                        sslVersionMapper.parse(stringValue, detectionLocation);
                if (parsedVersion.isPresent()) {
                    return Optional.of(new TLS(stringValue, parsedVersion.get()));
                }
            }
            return Optional.of(new Protocol(stringValue, detectionLocation));
        }

        return Optional.of(new Unknown(detectionLocation));
    }

    /**
     * Translates an SRTP protection profile list (e.g. {@code
     * "SRTP_AES128_CM_SHA1_80:SRTP_AEAD_AES_128_GCM"}), as passed to {@code
     * SSL_CTX_set_tlsext_use_srtp}, into an SRTP protocol node holding one entry per profile with
     * its algorithms and its two-byte identifier (RFC 5764, RFC 7714, RFC 8269, RFC 8723). Names
     * OpenSSL does not accept are skipped.
     */
    @Nonnull
    private static Optional<INode> translateSrtpProfiles(
            @Nonnull String profiles, @Nonnull DetectionLocation detectionLocation) {
        final List<com.ibm.mapper.model.CipherSuite> entries = new ArrayList<>();
        for (String rawName : profiles.split(":")) {
            final String name = rawName.trim();
            srtpProfileAlgorithms(name, detectionLocation)
                    .ifPresent(
                            algorithms ->
                                    entries.add(
                                            new com.ibm.mapper.model.CipherSuite(
                                                    name,
                                                    new AssetCollection(algorithms),
                                                    new IdentifierCollection(
                                                            List.of(
                                                                    new Identifier(
                                                                            "0x00",
                                                                            detectionLocation),
                                                                    new Identifier(
                                                                            SRTP_PROFILE_IDS.get(
                                                                                    name),
                                                                            detectionLocation))),
                                                    detectionLocation)));
        }
        if (entries.isEmpty()) {
            return Optional.empty();
        }
        final Protocol srtp = new Protocol("SRTP", detectionLocation);
        srtp.put(new CipherSuiteCollection(entries));
        return Optional.of(srtp);
    }

    /** SRTP protection profile names accepted by OpenSSL → the second byte of their identifier. */
    private static final Map<String, String> SRTP_PROFILE_IDS =
            Map.ofEntries(
                    Map.entry("SRTP_AES128_CM_SHA1_80", "0x01"),
                    Map.entry("SRTP_AES128_CM_SHA1_32", "0x02"),
                    Map.entry("SRTP_AEAD_AES_128_GCM", "0x07"),
                    Map.entry("SRTP_AEAD_AES_256_GCM", "0x08"),
                    Map.entry("SRTP_DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM", "0x09"),
                    Map.entry("SRTP_DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM", "0x0A"),
                    Map.entry("SRTP_ARIA_128_CTR_HMAC_SHA1_80", "0x0B"),
                    Map.entry("SRTP_ARIA_128_CTR_HMAC_SHA1_32", "0x0C"),
                    Map.entry("SRTP_ARIA_256_CTR_HMAC_SHA1_80", "0x0D"),
                    Map.entry("SRTP_ARIA_256_CTR_HMAC_SHA1_32", "0x0E"),
                    Map.entry("SRTP_AEAD_ARIA_128_GCM", "0x0F"),
                    Map.entry("SRTP_AEAD_ARIA_256_GCM", "0x10"));

    /**
     * The algorithms of an SRTP protection profile: a counter mode cipher with an HMAC-SHA1
     * authentication tag of 80 or 32 bits, or an AEAD cipher.
     */
    @Nonnull
    private static Optional<List<INode>> srtpProfileAlgorithms(
            @Nonnull String name, @Nonnull DetectionLocation detectionLocation) {
        return switch (name) {
            case "SRTP_AES128_CM_SHA1_80" ->
                    Optional.of(
                            List.of(
                                    new AES(128, new CTR(detectionLocation), detectionLocation),
                                    hmacSha1(80, detectionLocation)));
            case "SRTP_AES128_CM_SHA1_32" ->
                    Optional.of(
                            List.of(
                                    new AES(128, new CTR(detectionLocation), detectionLocation),
                                    hmacSha1(32, detectionLocation)));
            case "SRTP_AEAD_AES_128_GCM", "SRTP_DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM" ->
                    Optional.of(
                            List.of(new AES(128, new GCM(detectionLocation), detectionLocation)));
            case "SRTP_AEAD_AES_256_GCM", "SRTP_DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM" ->
                    Optional.of(
                            List.of(new AES(256, new GCM(detectionLocation), detectionLocation)));
            case "SRTP_ARIA_128_CTR_HMAC_SHA1_80" ->
                    Optional.of(
                            List.of(
                                    new Aria(128, new CTR(detectionLocation), detectionLocation),
                                    hmacSha1(80, detectionLocation)));
            case "SRTP_ARIA_128_CTR_HMAC_SHA1_32" ->
                    Optional.of(
                            List.of(
                                    new Aria(128, new CTR(detectionLocation), detectionLocation),
                                    hmacSha1(32, detectionLocation)));
            case "SRTP_ARIA_256_CTR_HMAC_SHA1_80" ->
                    Optional.of(
                            List.of(
                                    new Aria(256, new CTR(detectionLocation), detectionLocation),
                                    hmacSha1(80, detectionLocation)));
            case "SRTP_ARIA_256_CTR_HMAC_SHA1_32" ->
                    Optional.of(
                            List.of(
                                    new Aria(256, new CTR(detectionLocation), detectionLocation),
                                    hmacSha1(32, detectionLocation)));
            case "SRTP_AEAD_ARIA_128_GCM" ->
                    Optional.of(
                            List.of(new Aria(128, new GCM(detectionLocation), detectionLocation)));
            case "SRTP_AEAD_ARIA_256_GCM" ->
                    Optional.of(
                            List.of(new Aria(256, new GCM(detectionLocation), detectionLocation)));
            default -> Optional.empty();
        };
    }

    @Nonnull
    private static HMAC hmacSha1(int tagLength, @Nonnull DetectionLocation detectionLocation) {
        final HMAC hmac = new HMAC(new SHA(detectionLocation));
        hmac.put(new TagLength(tagLength, detectionLocation));
        return hmac;
    }

    /**
     * Translates an OpenSSL cipher string (e.g. {@code "ECDHE-RSA-AES256-GCM-SHA384:!aNULL"}), as
     * passed to {@code SSL_CTX_set_cipher_list} or {@code SSL_CTX_set_ciphersuites}, into one node
     * per cipher suite it names. Entries are separated by colons, commas or spaces. Entries that do
     * not name a single suite are skipped: exclusions and reordering ({@code !x}, {@code -x},
     * {@code +x}), directives ({@code @SECLEVEL=2}) and keywords that select a group of suites
     * ({@code HIGH}, {@code aNULL}, {@code DEFAULT}). The result is a {@link TLS} node holding the
     * suites as a {@link CipherSuiteCollection}, the shape the CBOM output reads cipher suites
     * from.
     */
    @Nonnull
    private static Optional<INode> translateCipherString(
            @Nonnull String cipherString, @Nonnull DetectionLocation detectionLocation) {
        final CipherSuiteMapper cipherSuiteMapper = new CipherSuiteMapper();
        final List<com.ibm.mapper.model.CipherSuite> suites = new ArrayList<>();
        for (String rawEntry : cipherString.split("[:, ]")) {
            final String entry = rawEntry.trim();
            if (entry.isEmpty() || "!-+@".indexOf(entry.charAt(0)) >= 0) {
                continue;
            }
            // suite names contain a hyphen (OpenSSL names) or start with "TLS_" (standard names);
            // keywords such as HIGH or aNULL do neither
            if (CipherSuiteMapper.findCipherSuite(entry).isPresent()
                    || entry.contains("-")
                    || entry.startsWith("TLS_")) {
                cipherSuiteMapper
                        .parse(entry, detectionLocation)
                        .filter(com.ibm.mapper.model.CipherSuite.class::isInstance)
                        .map(com.ibm.mapper.model.CipherSuite.class::cast)
                        .ifPresent(suites::add);
            }
        }
        if (suites.isEmpty()) {
            return Optional.empty();
        }
        final TLS tls = new TLS(detectionLocation);
        tls.put(new CipherSuiteCollection(suites));
        return Optional.of(tls);
    }

    /**
     * Splits a colon-separated OpenSSL algorithm list (e.g. {@code "MLKEM768:X25519"}) and maps
     * each entry with the given per-library mapper. An entry the mapper doesn't recognize is an
     * algorithm of the given kind named after the entry. The result is a single {@link
     * AssetCollection} node holding one child per entry.
     */
    @Nonnull
    private static Optional<INode> translateList(
            @Nonnull String list,
            @Nonnull IMapper mapper,
            @Nonnull Class<? extends IPrimitive> kindOfUnknownNames,
            @Nonnull DetectionLocation detectionLocation) {
        final List<INode> nodes = new ArrayList<>();
        for (String rawName : list.split(":")) {
            final String name = rawName.trim();
            if (name.isEmpty()) {
                continue;
            }
            final INode node =
                    mapper.parse(name, detectionLocation)
                            .<INode>map(n -> n)
                            .orElseGet(
                                    () ->
                                            new com.ibm.mapper.model.Algorithm(
                                                    name, kindOfUnknownNames, detectionLocation));
            nodes.add(node);
        }
        if (nodes.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(new AssetCollection(nodes));
    }
}
