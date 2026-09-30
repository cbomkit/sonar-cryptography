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
import com.ibm.engine.model.IterationCount;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.SaltSize;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.mapper.openssl.OpenSslKdfMapper;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyDerivationFunction;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.NumberOfIterations;
import com.ibm.mapper.model.PasswordBasedKeyDerivationFunction;
import com.ibm.mapper.model.SaltLength;
import com.ibm.mapper.model.functionality.KeyDerivation;
import com.ibm.mapper.utils.DetectionLocation;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.Optional;
import javax.annotation.Nonnull;

public final class CxxKeyDerivationFunctionContextTranslator
        implements IContextTranslation<AstNode> {

    @Override
    public @Nonnull Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<AstNode> value,
            @Nonnull IDetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {

        if (value instanceof ValueAction<AstNode>
                || value instanceof com.ibm.engine.model.Algorithm<AstNode>) {
            return new OpenSslKdfMapper()
                    .parse(value.asString(), detectionLocation)
                    .map(kdf -> withKeyDerivation(kdf, detectionLocation));
        } else if (value instanceof KeySize<AstNode> keySize) {
            return Optional.of(new KeyLength(keySize.getValue(), detectionLocation));
        } else if (value instanceof SaltSize<AstNode> saltSize) {
            return Optional.of(new SaltLength(saltSize.getValue(), detectionLocation));
        } else if (value instanceof IterationCount<AstNode> iterationCount) {
            return Optional.of(
                    new NumberOfIterations(iterationCount.getValue(), detectionLocation));
        }
        return Optional.empty();
    }

    /** A key derivation function is reported with the key derivation it performs. */
    @Nonnull
    private static INode withKeyDerivation(
            @Nonnull INode node, @Nonnull DetectionLocation detectionLocation) {
        if (node.is(KeyDerivationFunction.class)
                || node.is(PasswordBasedKeyDerivationFunction.class)) {
            node.put(new KeyDerivation(detectionLocation));
        }
        return node;
    }
}
