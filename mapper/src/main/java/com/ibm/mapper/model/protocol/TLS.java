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
package com.ibm.mapper.model.protocol;

import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Protocol;
import com.ibm.mapper.model.Version;
import com.ibm.mapper.model.collections.CipherSuiteCollection;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;

public final class TLS extends Protocol {

    public TLS(@Nonnull DetectionLocation detectionLocation) {
        super(new Protocol("TLS", detectionLocation), TLS.class);
    }

    public TLS(@Nonnull Version version) {
        super(new Protocol("TLSv" + version.asString(), version.getDetectionContext()), TLS.class);
        this.put(version);
    }

    /**
     * @param originalValue the detected algorithm/protocol string this version was parsed from
     *     (e.g. {@code "SSLv3"}, {@code "DTLSv1.2"}, {@code "TLSv1.2"}, or a language-specific
     *     constant name like Go's {@code "VersionSSL30"}); its {@code tls}/{@code ssl}/{@code dtls}
     *     family is preserved in the node's name instead of always labeling it {@code TLS}.
     */
    public TLS(@Nonnull String originalValue, @Nonnull Version version) {
        super(
                new Protocol(
                        namePrefix(originalValue) + "v" + version.asString(),
                        version.getDetectionContext()),
                TLS.class);
        this.put(version);
    }

    @Nonnull
    private static String namePrefix(@Nonnull String originalValue) {
        String lower = originalValue.toLowerCase();
        // "contains", not "startsWith": callers pass either a bare protocol string ("SSLv3",
        // "DTLSv1.2") or a language-specific constant name the family token is embedded in
        // (Go's "VersionSSL30", "VersionTLS12"). Check dtls before ssl since "dtls" itself
        // contains "ls" but not "ssl", so the two never collide.
        if (lower.contains("dtls")) {
            return "DTLS";
        }
        if (lower.contains("ssl")) {
            return "SSL";
        }
        return "TLS";
    }

    @Nonnull
    public Optional<Version> getVersion() {
        INode node = this.getChildren().get(Version.class);
        if (node == null) {
            return Optional.empty();
        }
        return Optional.of((Version) node);
    }

    @Nonnull
    public Optional<CipherSuiteCollection> getCipherSuits() {
        INode node = this.getChildren().get(CipherSuiteCollection.class);
        if (node == null) {
            return Optional.empty();
        }
        return Optional.of((CipherSuiteCollection) node);
    }
}
