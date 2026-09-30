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
import com.ibm.mapper.mapper.ssl.CipherSuiteMapper;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.collections.CipherSuiteCollection;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/** Maps an OpenSSL cipher string to the TLS cipher suites it names. */
public class OpenSslCipherStringMapper implements IMapper {

    /**
     * Maps an OpenSSL cipher string (e.g. {@code "ECDHE-RSA-AES256-GCM-SHA384:!aNULL"}), as passed
     * to {@code SSL_CTX_set_cipher_list} or {@code SSL_CTX_set_ciphersuites}, into one node per
     * cipher suite it names. Entries are separated by colons, commas or spaces. Entries that do not
     * name a single suite are skipped: exclusions and reordering ({@code !x}, {@code -x}, {@code
     * +x}), directives ({@code @SECLEVEL=2}) and keywords that select a group of suites ({@code
     * HIGH}, {@code aNULL}, {@code DEFAULT}). The result is a {@link CipherSuiteCollection} of the
     * suites: the cipher suites of the TLS protocol they are configured on.
     */
    @Nonnull
    @Override
    public Optional<? extends INode> parse(
            @Nullable final String cipherString, @Nonnull DetectionLocation detectionLocation) {
        if (cipherString == null) {
            return Optional.empty();
        }
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
        return Optional.of(new CipherSuiteCollection(suites));
    }
}
