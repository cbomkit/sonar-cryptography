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
package com.ibm.plugin.rules.detection.openssl.legacy;

import com.ibm.engine.detection.ResolvedValue;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.Protocol;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.factory.IValueFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.Map;
import java.util.Optional;
import java.util.function.BiFunction;
import java.util.function.IntUnaryOperator;
import javax.annotation.Nonnull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Resolves an OpenSSL numeric-or-bare-name argument (e.g. the curve NID of {@code
 * EC_KEY_new_by_curve_name(_ex)} / {@code EC_GROUP_new_by_curve_name(_ex)} / {@code
 * EVP_PKEY_CTX_set_ec_paramgen_curve_nid}, the DH group NID of {@code EVP_PKEY_CTX_set_dh_nid}, or
 * the protocol version of {@code SSL_(CTX_)set_min/max_proto_version}) to the identifier string the
 * corresponding {@code Cxx*ContextTranslator} switches on, using caller-supplied lookup tables.
 *
 * <p>The engine hands this factory a numeric code (e.g. {@code 415}) when the argument is a numeric
 * literal, or when it is an unscoped enum constant with an explicit {@code = constantExpression}
 * value. An unscoped enum constant with no explicit value instead resolves to its own declared name
 * (e.g. {@code "NID_X9_62_prime256v1"}), looked up in {@code byName}. A plain identifier with no
 * attached symbol at all (such as an unexpanded OpenSSL macro constant when no include directories
 * are configured) is not a resolved value and never reaches this factory, so that shape produces no
 * finding. A code outside both tables resolves to nothing.
 */
public final class OpenSSLNidLookupFactory implements IValueFactory<AstNode> {

    private static final Logger LOGGER = LoggerFactory.getLogger(OpenSSLNidLookupFactory.class);

    /** OpenSSL curve NID codes (obj_mac.h) → curve identifier strings. */
    public static final Map<Integer, String> CURVE_BY_CODE =
            Map.ofEntries(
                    Map.entry(409, "EC-P192"),
                    Map.entry(415, "EC-P256"),
                    Map.entry(714, "EC-SECP256K1"),
                    Map.entry(715, "EC-P384"),
                    Map.entry(716, "EC-P521"),
                    Map.entry(927, "EC-BRAINPOOLP256R1"),
                    Map.entry(931, "EC-BRAINPOOLP384R1"),
                    Map.entry(933, "EC-BRAINPOOLP512R1"));

    /** OpenSSL curve NID constant names → curve identifier strings. */
    public static final Map<String, String> CURVE_BY_NAME =
            Map.ofEntries(
                    Map.entry("NID_X9_62_prime192v1", "EC-P192"),
                    Map.entry("NID_X9_62_prime256v1", "EC-P256"),
                    Map.entry("NID_secp256k1", "EC-SECP256K1"),
                    Map.entry("NID_secp384r1", "EC-P384"),
                    Map.entry("NID_secp521r1", "EC-P521"),
                    Map.entry("NID_brainpoolP256r1", "EC-BRAINPOOLP256R1"),
                    Map.entry("NID_brainpoolP384r1", "EC-BRAINPOOLP384R1"),
                    Map.entry("NID_brainpoolP512r1", "EC-BRAINPOOLP512R1"));

    /** OpenSSL named DH group NID codes (obj_mac.h) → key-length identifier strings. */
    public static final Map<Integer, String> DH_GROUP_BY_CODE =
            Map.ofEntries(
                    Map.entry(1126, "DH-2048"), // NID_ffdhe2048
                    Map.entry(1127, "DH-3072"), // NID_ffdhe3072
                    Map.entry(1128, "DH-4096")); // NID_ffdhe4096

    /** Numeric OpenSSL protocol version codes → version strings. */
    public static final Map<Integer, String> PROTO_VERSION_BY_CODE =
            Map.ofEntries(
                    Map.entry(0x0300, "SSLv3.0"),
                    Map.entry(0x0301, "TLSv1.0"),
                    Map.entry(0x0302, "TLSv1.1"),
                    Map.entry(0x0303, "TLSv1.2"),
                    Map.entry(0x0304, "TLSv1.3"),
                    Map.entry(0xFEFF, "DTLSv1.0"),
                    Map.entry(0xFEFD, "DTLSv1.2"),
                    Map.entry(0x0100, "DTLSv1.0")); // DTLS1_BAD_VER

    /**
     * OpenSSL version constant names → version strings, used when an unscoped enum constant with no
     * explicit value resolves to its own declared name instead of a numeric code.
     */
    public static final Map<String, String> PROTO_VERSION_BY_NAME =
            Map.ofEntries(
                    Map.entry("SSL3_VERSION", "SSLv3.0"),
                    Map.entry("TLS1_VERSION", "TLSv1.0"),
                    Map.entry("TLS1_1_VERSION", "TLSv1.1"),
                    Map.entry("TLS1_2_VERSION", "TLSv1.2"),
                    Map.entry("TLS1_3_VERSION", "TLSv1.3"),
                    Map.entry("DTLS1_VERSION", "DTLSv1.0"),
                    Map.entry("DTLS1_2_VERSION", "DTLSv1.2"),
                    Map.entry("DTLS1_BAD_VER", "DTLSv1.0"));

    /** Widens an {@code int} unchanged; the default {@code codeMask}. */
    private static final IntUnaryOperator NO_MASK = code -> code;

    @Nonnull private final Map<Integer, String> byCode;
    @Nonnull private final Map<String, String> byName;
    @Nonnull private final IntUnaryOperator codeMask;
    @Nonnull private final BiFunction<String, AstNode, IValue<AstNode>> valueConstructor;

    public OpenSSLNidLookupFactory() {
        this(CURVE_BY_CODE, CURVE_BY_NAME);
    }

    public OpenSSLNidLookupFactory(
            @Nonnull Map<Integer, String> byCode, @Nonnull Map<String, String> byName) {
        this(byCode, byName, NO_MASK, ValueAction::new);
    }

    /**
     * @param codeMask applied to a numeric argument's {@code int} value before the {@code byCode}
     *     lookup (e.g. {@code code -> code & 0xFFFF} to drop width padding on a protocol-version
     *     code); {@link #NO_MASK} for callers with no such padding.
     * @param valueConstructor builds the {@link IValue} the resolved string is wrapped in (e.g.
     *     {@link ValueAction} for a plain identifier, {@link Protocol} for a protocol version).
     */
    public OpenSSLNidLookupFactory(
            @Nonnull Map<Integer, String> byCode,
            @Nonnull Map<String, String> byName,
            @Nonnull IntUnaryOperator codeMask,
            @Nonnull BiFunction<String, AstNode, IValue<AstNode>> valueConstructor) {
        this.byCode = byCode;
        this.byName = byName;
        this.codeMask = codeMask;
        this.valueConstructor = valueConstructor;
    }

    @Override
    @Nonnull
    public Optional<IValue<AstNode>> apply(@Nonnull ResolvedValue<Object, AstNode> resolvedValue) {
        final Object value = resolvedValue.value();
        String resolved = null;

        if (value instanceof Number number) {
            resolved = byCode.get(codeMask.applyAsInt(number.intValue()));
        } else if (value instanceof String str) {
            resolved = byName.get(str);
            if (resolved == null) {
                final Integer code = parseNumeric(str);
                if (code != null) {
                    resolved = byCode.get(codeMask.applyAsInt(code));
                }
            }
        }

        if (resolved != null) {
            LOGGER.debug("Resolved NID argument {} → \"{}\"", value, resolved);
            return Optional.of(valueConstructor.apply(resolved, resolvedValue.tree()));
        }
        LOGGER.debug(
                "Could not map NID argument value: {} ({})",
                value,
                value == null ? "null" : value.getClass().getSimpleName());
        return Optional.empty();
    }

    /** Parses a decimal or hex ("0x19f") NID literal, tolerating integer suffixes. */
    private static Integer parseNumeric(@Nonnull String raw) {
        String s = raw.trim().replaceAll("[uUlL]+$", "");
        try {
            if (s.length() > 2 && (s.startsWith("0x") || s.startsWith("0X"))) {
                return Integer.parseInt(s.substring(2), 16);
            }
            return Integer.parseInt(s);
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
