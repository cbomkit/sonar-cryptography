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
package com.ibm.plugin.translation.translator.contexts;

import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.CipherAction;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.DetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.mapper.openssl.OpenSslCipherMapper;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.functionality.Decrypt;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.mapper.utils.DetectionLocation;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.Optional;
import javax.annotation.Nonnull;

public final class CxxCipherContextTranslator implements IContextTranslation<AstNode> {

    @Override
    public @Nonnull Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<AstNode> value,
            @Nonnull DetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {

        if (value instanceof CipherAction<AstNode> cipherAction) {
            return switch (cipherAction.getAction()) {
                case ENCRYPT -> Optional.of(new Encrypt(detectionLocation));
                case DECRYPT -> Optional.of(new Decrypt(detectionLocation));
                default -> Optional.empty();
            };
        }

        // the key size given to a legacy key setup function, e.g. the bits of AES_set_encrypt_key
        if (value instanceof KeySize<AstNode> keySize) {
            return Optional.of(new KeyLength(keySize.getValue(), detectionLocation));
        }

        if (value instanceof ValueAction<AstNode> || value instanceof Algorithm<AstNode>) {
            // a legacy cipher function takes its key length from the key setup of its key
            final boolean legacy =
                    detectionContext instanceof DetectionContext context
                            && context.get("kind").filter("LEGACY"::equals).isPresent();
            final OpenSslCipherMapper mapper = new OpenSslCipherMapper();
            return (legacy
                            ? mapper.parseLegacy(value.asString(), detectionLocation)
                            : mapper.parse(value.asString(), detectionLocation))
                    .map(node -> node);
        }

        return Optional.empty();
    }
}
