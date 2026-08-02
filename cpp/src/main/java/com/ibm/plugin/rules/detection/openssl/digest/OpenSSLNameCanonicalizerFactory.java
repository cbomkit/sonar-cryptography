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
package com.ibm.plugin.rules.detection.openssl.digest;

import com.ibm.engine.detection.ResolvedValue;
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.factory.IValueFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.Map;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Resolves an OpenSSL bare-name string argument (e.g. a digest {@code md_name} like {@code
 * "SHA256"}, or an EC group name like {@code "P-256"}) to the identifier string the corresponding
 * {@code Cxx*ContextTranslator} switches on, using a caller-supplied canonicalization table. Names
 * already in a recognized form, or not recognized at all, pass through unchanged, so the
 * translator's own {@code default -> Optional.empty()} decides whether they surface.
 */
public final class OpenSSLNameCanonicalizerFactory implements IValueFactory<AstNode> {

    /**
     * {@code md_name} argument (e.g. {@code EVP_PKEY_CTX_set_rsa_mgf1_md_name}) → {@code
     * "SHA-256"}.
     */
    public static final Map<String, String> DIGEST_NAMES =
            Map.ofEntries(
                    Map.entry("SHA1", "SHA-1"),
                    Map.entry("SHA224", "SHA-224"),
                    Map.entry("SHA256", "SHA-256"),
                    Map.entry("SHA384", "SHA-384"),
                    Map.entry("SHA512", "SHA-512"),
                    Map.entry("SHA512-224", "SHA-512/224"),
                    Map.entry("SHA512-256", "SHA-512/256"));

    /** Curve/group name argument (e.g. {@code EVP_PKEY_CTX_set_group_name}) → {@code "EC-P256"}. */
    public static final Map<String, String> GROUP_NAMES =
            Map.ofEntries(
                    Map.entry("P-192", "EC-P192"),
                    Map.entry("PRIME192V1", "EC-P192"),
                    Map.entry("P-256", "EC-P256"),
                    Map.entry("PRIME256V1", "EC-P256"),
                    Map.entry("P-384", "EC-P384"),
                    Map.entry("SECP384R1", "EC-P384"),
                    Map.entry("P-521", "EC-P521"),
                    Map.entry("SECP521R1", "EC-P521"),
                    Map.entry("SECP256K1", "EC-SECP256K1"),
                    Map.entry("BRAINPOOLP256R1", "EC-BRAINPOOLP256R1"),
                    Map.entry("BRAINPOOLP384R1", "EC-BRAINPOOLP384R1"),
                    Map.entry("BRAINPOOLP512R1", "EC-BRAINPOOLP512R1"));

    @Nonnull private final Map<String, String> table;

    public OpenSSLNameCanonicalizerFactory(@Nonnull Map<String, String> table) {
        this.table = table;
    }

    @Override
    @Nonnull
    public Optional<IValue<AstNode>> apply(@Nonnull ResolvedValue<Object, AstNode> resolvedValue) {
        final Object value = resolvedValue.value();
        if (!(value instanceof String str)) {
            return Optional.empty();
        }
        return Optional.of(new Algorithm<>(canonicalize(table, str), resolvedValue.tree()));
    }

    /**
     * Normalizes {@code name} against {@code table} (uppercased, trimmed lookup). A name already in
     * a recognized form, or not recognized at all, passes through unchanged.
     */
    @Nonnull
    public static String canonicalize(@Nonnull Map<String, String> table, @Nonnull String name) {
        return table.getOrDefault(name.toUpperCase().trim(), name);
    }
}
