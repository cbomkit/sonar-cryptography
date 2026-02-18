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

import com.ibm.engine.model.IAction;
import com.ibm.engine.model.factory.IActionFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Factory for creating OpenSSL version detection values.
 *
 * <p>This factory creates {@link OpenSSLVersionValue} instances which extract and resolve version
 * parameters from SSL_CTX_set_min/max_proto_version function calls.
 *
 * <p>Used as a workaround for C++ detection engine limitations with parameter extraction via the
 * builder API.
 */
public final class OpenSSLVersionDetectionFactory implements IActionFactory<AstNode> {

    @Nonnull private final String kind; // "MIN" or "MAX"

    public OpenSSLVersionDetectionFactory(@Nonnull String kind) {
        this.kind = kind;
    }

    @Nonnull
    @Override
    public Optional<IAction<AstNode>> apply(@Nonnull AstNode astNode) {
        return Optional.of(new OpenSSLVersionValue(kind, astNode));
    }
}
