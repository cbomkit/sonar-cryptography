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
package com.ibm.plugin.rules.detection.openssl.signature;

import com.ibm.engine.detection.ResolvedValue;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.SaltSize;
import com.ibm.engine.model.Size;
import com.ibm.engine.model.factory.IValueFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Resolves the RSA-PSS salt length argument of {@code EVP_PKEY_CTX_set_rsa_pss_saltlen} and {@code
 * EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen}, given in bytes, to a salt size in bits. The negative
 * special values ({@code RSA_PSS_SALTLEN_DIGEST}, {@code RSA_PSS_SALTLEN_MAX}, ...) select a length
 * derived from the digest or the key and resolve to nothing, as does an argument that is not an
 * integer.
 */
public final class OpenSSLSaltLengthFactory implements IValueFactory<AstNode> {

    @Override
    @Nonnull
    public Optional<IValue<AstNode>> apply(@Nonnull ResolvedValue<Object, AstNode> resolvedValue) {
        if (resolvedValue.value() instanceof Number bytes && bytes.intValue() > 0) {
            return Optional.of(
                    new SaltSize<>(bytes.intValue() * 8, Size.UnitType.BIT, resolvedValue.tree()));
        }
        return Optional.empty();
    }
}
