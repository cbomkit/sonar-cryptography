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
package com.ibm.plugin.rules.detection.openssl.keyagreement;

import com.ibm.engine.detection.ResolvedValue;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.factory.IValueFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.sonar.cxx.parser.CxxGrammarImpl;
import org.sonar.cxx.parser.CxxPunctuator;

/**
 * Resolves an HPKE suite (RFC 9180) to the identifier {@code "<KEM>,<KDF>,<AEAD>"}, e.g. {@code
 * "X25519,HKDF-SHA256,AES-128-GCM"}, that {@code CxxKeyAgreementContextTranslator} turns into an
 * HPKE node. The suite can be given as:
 *
 * <ul>
 *   <li>the string passed to {@code OSSL_HPKE_str2suite}, e.g. {@code "x25519,hkdf-sha256,
 *       aes-128-gcm"}, where each part is a name or its numeric identifier ({@code "0x20"}, {@code
 *       "32"});
 *   <li>an {@code OSSL_HPKE_SUITE} brace initializer, e.g. {@code {OSSL_HPKE_KEM_ID_P256,
 *       OSSL_HPKE_KDF_ID_HKDF_SHA256, OSSL_HPKE_AEAD_ID_AES_GCM_256}};
 *   <li>the {@code OSSL_HPKE_SUITE_DEFAULT} macro.
 * </ul>
 *
 * A suite with an unknown part resolves to nothing.
 */
public final class OpenSSLHpkeSuiteFactory implements IValueFactory<AstNode> {

    /** The suite {@code OSSL_HPKE_SUITE_DEFAULT} stands for. */
    private static final String DEFAULT_SUITE = "X25519,HKDF-SHA256,AES-128-GCM";

    private static final Map<Integer, String> KEM_BY_ID =
            Map.of(0x10, "P-256", 0x11, "P-384", 0x12, "P-521", 0x20, "X25519", 0x21, "X448");

    private static final Map<String, String> KEM_BY_NAME =
            Map.ofEntries(
                    Map.entry("P-256", "P-256"),
                    Map.entry("P-384", "P-384"),
                    Map.entry("P-521", "P-521"),
                    Map.entry("X25519", "X25519"),
                    Map.entry("X448", "X448"),
                    Map.entry("OSSL_HPKE_KEM_ID_P256", "P-256"),
                    Map.entry("OSSL_HPKE_KEM_ID_P384", "P-384"),
                    Map.entry("OSSL_HPKE_KEM_ID_P521", "P-521"),
                    Map.entry("OSSL_HPKE_KEM_ID_X25519", "X25519"),
                    Map.entry("OSSL_HPKE_KEM_ID_X448", "X448"));

    private static final Map<Integer, String> KDF_BY_ID =
            Map.of(1, "HKDF-SHA256", 2, "HKDF-SHA384", 3, "HKDF-SHA512");

    private static final Map<String, String> KDF_BY_NAME =
            Map.ofEntries(
                    Map.entry("HKDF-SHA256", "HKDF-SHA256"),
                    Map.entry("HKDF-SHA384", "HKDF-SHA384"),
                    Map.entry("HKDF-SHA512", "HKDF-SHA512"),
                    Map.entry("OSSL_HPKE_KDF_ID_HKDF_SHA256", "HKDF-SHA256"),
                    Map.entry("OSSL_HPKE_KDF_ID_HKDF_SHA384", "HKDF-SHA384"),
                    Map.entry("OSSL_HPKE_KDF_ID_HKDF_SHA512", "HKDF-SHA512"));

    /** The export-only AEAD is 0xff in a suite string and 0xFFFF in an {@code OSSL_HPKE_SUITE}. */
    private static final Map<Integer, String> AEAD_BY_ID =
            Map.of(
                    1, "AES-128-GCM",
                    2, "AES-256-GCM",
                    3, "CHACHA20-POLY1305",
                    0xFF, "EXPORTER",
                    0xFFFF, "EXPORTER");

    private static final Map<String, String> AEAD_BY_NAME =
            Map.ofEntries(
                    Map.entry("AES-128-GCM", "AES-128-GCM"),
                    Map.entry("AES-256-GCM", "AES-256-GCM"),
                    Map.entry("CHACHA20-POLY1305", "CHACHA20-POLY1305"),
                    Map.entry("EXPORTER", "EXPORTER"),
                    Map.entry("OSSL_HPKE_AEAD_ID_AES_GCM_128", "AES-128-GCM"),
                    Map.entry("OSSL_HPKE_AEAD_ID_AES_GCM_256", "AES-256-GCM"),
                    Map.entry("OSSL_HPKE_AEAD_ID_CHACHA_POLY1305", "CHACHA20-POLY1305"),
                    Map.entry("OSSL_HPKE_AEAD_ID_EXPORTONLY", "EXPORTER"));

    @Override
    @Nonnull
    public Optional<IValue<AstNode>> apply(@Nonnull ResolvedValue<Object, AstNode> resolvedValue) {
        final List<String> parts;
        if (resolvedValue.value() instanceof AstNode node
                && node.is(CxxGrammarImpl.bracedInitList)) {
            parts = initializerElements(node);
        } else if (resolvedValue.value() instanceof String str) {
            if ("OSSL_HPKE_SUITE_DEFAULT".equals(str.trim())) {
                return Optional.of(new ValueAction<>(DEFAULT_SUITE, resolvedValue.tree()));
            }
            parts = List.of(str.split(",", -1));
        } else {
            return Optional.empty();
        }
        if (parts.size() != 3) {
            return Optional.empty();
        }
        final String kem = lookup(parts.get(0), KEM_BY_NAME, KEM_BY_ID);
        final String kdf = lookup(parts.get(1), KDF_BY_NAME, KDF_BY_ID);
        final String aead = lookup(parts.get(2), AEAD_BY_NAME, AEAD_BY_ID);
        if (kem == null || kdf == null || aead == null) {
            return Optional.empty();
        }
        return Optional.of(
                new ValueAction<>(String.join(",", kem, kdf, aead), resolvedValue.tree()));
    }

    /** The source text of each element of a brace initializer. */
    @Nonnull
    private static List<String> initializerElements(@Nonnull AstNode bracedInitList) {
        final AstNode initializerList =
                bracedInitList.getFirstChild(CxxGrammarImpl.initializerList);
        final List<String> elements = new ArrayList<>();
        if (initializerList == null) {
            return elements;
        }
        for (AstNode element : initializerList.getChildren()) {
            if (!element.is(CxxPunctuator.COMMA)) {
                elements.add(element.getTokenValue());
            }
        }
        return elements;
    }

    @Nullable private static String lookup(
            @Nonnull String part,
            @Nonnull Map<String, String> byName,
            @Nonnull Map<Integer, String> byId) {
        final String trimmed = part.trim();
        final String name = byName.get(trimmed.toUpperCase(Locale.ROOT));
        if (name != null) {
            return name;
        }
        try {
            return byId.get(Integer.decode(trimmed));
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
