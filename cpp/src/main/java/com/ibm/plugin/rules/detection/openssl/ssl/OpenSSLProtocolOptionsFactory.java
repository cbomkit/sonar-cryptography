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
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.annotation.Nonnull;

/**
 * Resolves the protocol versions disabled by the options of {@code SSL_CTX_set_options(ctx, op)} or
 * {@code SSL_set_options(ssl, op)}, e.g. {@code SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1}, to the
 * colon-separated list of these versions, lowest first, e.g. {@code TLSv1.0:TLSv1.1}. The options
 * set on a context add up, so the range of versions they leave is resolved from the versions
 * disabled by all the options of the context (see {@code ProtocolVersionReorganizer}); options that
 * disable no version resolve to nothing.
 *
 * <p>The versions are those of TLS, or of DTLS for the {@code SSL_OP_NO_DTLS*} options. SSL 3.0 is
 * not built into OpenSSL by default since 1.1.0, so {@code SSL_OP_NO_SSLv3} disables no version.
 * The options are read by their names: {@code SSL_OP_NO_DTLSv1} has the value of {@code
 * SSL_OP_NO_TLSv1}, and which one is meant depends on the method of the context.
 */
public final class OpenSSLProtocolOptionsFactory implements IValueFactory<AstNode> {

    /** The option disabling each version, lowest version first. */
    private static final Map<String, String> VERSION_OPTIONS = new LinkedHashMap<>();

    static {
        VERSION_OPTIONS.put("SSL_OP_NO_TLSv1", "TLSv1.0");
        VERSION_OPTIONS.put("SSL_OP_NO_TLSv1_1", "TLSv1.1");
        VERSION_OPTIONS.put("SSL_OP_NO_TLSv1_2", "TLSv1.2");
        VERSION_OPTIONS.put("SSL_OP_NO_TLSv1_3", "TLSv1.3");
        VERSION_OPTIONS.put("SSL_OP_NO_DTLSv1", "DTLSv1.0");
        VERSION_OPTIONS.put("SSL_OP_NO_DTLSv1_2", "DTLSv1.2");
    }

    @Nonnull
    @Override
    public Optional<IValue<AstNode>> apply(@Nonnull ResolvedValue<Object, AstNode> resolvedValue) {
        if (!(resolvedValue.value() instanceof String options)) {
            return Optional.empty();
        }
        final Set<String> flags =
                Stream.of(options.split("\\|")).map(String::trim).collect(Collectors.toSet());
        final String disabled =
                VERSION_OPTIONS.entrySet().stream()
                        .filter(option -> flags.contains(option.getKey()))
                        .map(Map.Entry::getValue)
                        .collect(Collectors.joining(":"));
        if (disabled.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(new Protocol<>(disabled, resolvedValue.tree()));
    }
}
