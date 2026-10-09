/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2026 PQCA
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
package com.ibm.mapper.mapper.openssl;

import com.ibm.mapper.mapper.IMapper;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Identifier;
import com.ibm.mapper.model.Protocol;
import com.ibm.mapper.model.TagLength;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.Aria;
import com.ibm.mapper.model.algorithms.HMAC;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.model.collections.AssetCollection;
import com.ibm.mapper.model.collections.CipherSuiteCollection;
import com.ibm.mapper.model.collections.IdentifierCollection;
import com.ibm.mapper.model.mode.CTR;
import com.ibm.mapper.model.mode.GCM;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/** Maps the SRTP protection profiles given to {@code SSL_CTX_set_tlsext_use_srtp} to the model. */
public class OpenSslSrtpProfileMapper implements IMapper {

    /**
     * Maps an SRTP protection profile list (e.g. {@code
     * "SRTP_AES128_CM_SHA1_80:SRTP_AEAD_AES_128_GCM"}), as passed to {@code
     * SSL_CTX_set_tlsext_use_srtp}, into an SRTP protocol node holding one entry per profile with
     * its algorithms and its two-byte identifier (RFC 5764, RFC 7714, RFC 8269, RFC 8723). Names
     * OpenSSL does not accept are skipped.
     */
    @Nonnull
    @Override
    public Optional<? extends INode> parse(
            @Nullable final String profiles, @Nonnull DetectionLocation detectionLocation) {
        if (profiles == null) {
            return Optional.empty();
        }
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
}
