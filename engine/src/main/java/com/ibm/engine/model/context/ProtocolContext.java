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
package com.ibm.engine.model.context;

import java.util.Map;
import javax.annotation.Nonnull;

public class ProtocolContext extends DetectionContext {

    public enum Kind {
        TLS,
        // TLS signature-algorithm list configuration (e.g. SSL_CTX_set1_sigalgs_list).
        TLS_SIGNATURE_ALGORITHMS,
        // TLS supported-groups (key-exchange) list configuration (e.g. SSL_CTX_set1_groups_list).
        TLS_GROUPS,
        // TLS protocol versions disabled by options (e.g. SSL_CTX_set_options with
        // SSL_OP_NO_TLSv1), the minimum version (e.g. SSL_CTX_set_min_proto_version) and the
        // maximum version (e.g. SSL_CTX_set_max_proto_version): the settings made on a context
        // together bound the range of versions it uses.
        TLS_DISABLED_VERSIONS,
        TLS_MINIMUM_VERSION,
        TLS_MAXIMUM_VERSION,
        // SRTP protection profile list configuration (e.g. SSL_CTX_set_tlsext_use_srtp).
        SRTP,
        NONE,
    }

    public ProtocolContext(@Nonnull ProtocolContext.Kind kind) {
        super(Map.of("kind", kind.name()));
    }

    public ProtocolContext() {
        super(Map.of("kind", Kind.NONE.name()));
    }

    public ProtocolContext(@Nonnull Map<String, String> properties) {
        super(properties);
    }

    @Nonnull
    @Override
    public Class<? extends DetectionContext> type() {
        return ProtocolContext.class;
    }

    @Nonnull
    public Kind kind() {
        try {
            return Kind.valueOf(get("kind").orElse(Kind.NONE.name()));
        } catch (IllegalArgumentException e) {
            return Kind.NONE;
        }
    }
}
