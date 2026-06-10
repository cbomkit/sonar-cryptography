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

import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.utils.DetectionLocation;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Translator for C++ secret key detection contexts.
 *
 * <p>This translator handles the translation of secret key-related detection values to the mapper
 * model nodes.
 */
public final class CxxSecretKeyContextTranslator implements IContextTranslation<AstNode> {

    public CxxSecretKeyContextTranslator() {
        // nothing
    }

    @Override
    @Nonnull
    public Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<AstNode> value,
            @Nonnull IDetectionContext detectionValueContext,
            @Nonnull DetectionLocation detectionLocation) {
        // Handle key sizes (bytes/bit units) → KeyLength
        if (value instanceof KeySize<?> keySize) {
            int bits = keySize.getValue();
            if (keySize.getUnitType() == Size.UnitType.BYTE) {
                bits = bits * 8;
            }
            return Optional.of(new com.ibm.mapper.model.KeyLength(bits, detectionLocation));
        }

        // Handle key-related actions (generation / KDF / encapsulation)
        if (value instanceof KeyAction<?> keyAction) {
            switch (keyAction.getAction()) {
                case SECRET_KEY_GENERATION, GENERATION ->
                        Optional.of(
                                new com.ibm.mapper.model.functionality.KeyGeneration(
                                        com.ibm.mapper.model.functionality.KeyGeneration.Specification.SECRET_KEY,
                                        detectionLocation));
                case KDF -> Optional.of(new com.ibm.mapper.model.functionality.KeyDerivation(detectionLocation));
                case ENCAPSULATION -> Optional.of(new com.ibm.mapper.model.functionality.Encapsulate(detectionLocation));
                default -> Optional.empty();
            }
        }

        return Optional.empty();
    }
}
