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
package com.ibm.plugin.rules.detection.openssl.ssl;

import com.ibm.engine.detection.ResolvedValue;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.Protocol;
import com.ibm.engine.model.factory.IValueFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.annotation.Nonnull;

/**
 * Resolves the protocol versions disabled by the options of {@code SSL_CTX_set_options(ctx, op)} or
 * {@code SSL_set_options(ssl, op)}, e.g. {@code SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1}, to a bound of
 * the range of versions OpenSSL then uses. OpenSSL uses the lowest run of versions that are not
 * disabled: a version above a disabled one is not used, e.g. with only {@code SSL_OP_NO_TLSv1_1}
 * the highest version used is TLS 1.0. The {@link Bound#MINIMUM minimum} is resolved when the
 * options raise it and the {@link Bound#MAXIMUM maximum} when they lower it, as {@code
 * SSL_CTX_set_min_proto_version} and {@code SSL_CTX_set_max_proto_version} set them; options that
 * leave the bound as it is resolve to nothing.
 *
 * <p>The versions are those of TLS, or of DTLS for the {@code SSL_OP_NO_DTLS*} options. SSL 3.0 is
 * not built into OpenSSL by default since 1.1.0, so {@code SSL_OP_NO_SSLv3} changes no bound. The
 * options are read by their names: {@code SSL_OP_NO_DTLSv1} has the value of {@code
 * SSL_OP_NO_TLSv1}, and which one is meant depends on the method of the context.
 */
public final class OpenSSLProtocolOptionsFactory implements IValueFactory<AstNode> {

    /** The bound of the range of versions resolved. */
    public enum Bound {
        MINIMUM,
        MAXIMUM
    }

    private static final List<String> TLS_VERSIONS =
            List.of("TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3");

    private static final Map<String, String> TLS_OPTIONS =
            Map.of(
                    "SSL_OP_NO_TLSv1", "TLSv1.0",
                    "SSL_OP_NO_TLSv1_1", "TLSv1.1",
                    "SSL_OP_NO_TLSv1_2", "TLSv1.2",
                    "SSL_OP_NO_TLSv1_3", "TLSv1.3");

    private static final List<String> DTLS_VERSIONS = List.of("DTLSv1.0", "DTLSv1.2");

    private static final Map<String, String> DTLS_OPTIONS =
            Map.of(
                    "SSL_OP_NO_DTLSv1", "DTLSv1.0",
                    "SSL_OP_NO_DTLSv1_2", "DTLSv1.2");

    @Nonnull private final Bound bound;

    public OpenSSLProtocolOptionsFactory(@Nonnull Bound bound) {
        this.bound = bound;
    }

    @Nonnull
    @Override
    public Optional<IValue<AstNode>> apply(@Nonnull ResolvedValue<Object, AstNode> resolvedValue) {
        if (!(resolvedValue.value() instanceof String options)) {
            return Optional.empty();
        }
        final Set<String> flags =
                Stream.of(options.split("\\|")).map(String::trim).collect(Collectors.toSet());
        final boolean tls = flags.stream().anyMatch(TLS_OPTIONS::containsKey);
        final List<String> versions = tls ? TLS_VERSIONS : DTLS_VERSIONS;
        final Map<String, String> disabling = tls ? TLS_OPTIONS : DTLS_OPTIONS;
        final Set<String> disabled =
                flags.stream()
                        .map(disabling::get)
                        .filter(Objects::nonNull)
                        .collect(Collectors.toSet());
        if (disabled.isEmpty()) {
            return Optional.empty();
        }
        int lowest = 0;
        while (lowest < versions.size() && disabled.contains(versions.get(lowest))) {
            lowest++;
        }
        if (lowest == versions.size()) {
            return Optional.empty();
        }
        int highest = lowest;
        while (highest + 1 < versions.size() && !disabled.contains(versions.get(highest + 1))) {
            highest++;
        }
        if (bound == Bound.MINIMUM && lowest > 0) {
            return Optional.of(new Protocol<>(versions.get(lowest), resolvedValue.tree()));
        }
        if (bound == Bound.MAXIMUM && highest < versions.size() - 1) {
            return Optional.of(new Protocol<>(versions.get(highest), resolvedValue.tree()));
        }
        return Optional.empty();
    }
}
