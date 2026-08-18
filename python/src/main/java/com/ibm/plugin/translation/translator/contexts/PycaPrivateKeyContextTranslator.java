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

import com.ibm.engine.model.Curve;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.context.DetectionContext;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.mapper.pyca.PycaCurveMapper;
import com.ibm.mapper.mapper.pyca.PycaKeyBasedAlgorithmMapper;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Key;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.PrivateKey;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.sonar.plugins.python.api.tree.Tree;

@SuppressWarnings("java:S1301")
public final class PycaPrivateKeyContextTranslator implements IContextTranslation<Tree> {

    @Override
    public @Nonnull Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<Tree> value,
            @Nonnull IDetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {
        if (value instanceof KeyAction<Tree>
                && detectionContext instanceof DetectionContext context) {
            return getPrivateKey(context, null, detectionLocation);
        } else if (value instanceof KeySize<Tree> keySize) {
            if (detectionContext instanceof DetectionContext context
                    && context.get("algorithm").isPresent()) {
                return getPrivateKey(context, keySize.getValue(), detectionLocation);
            }
            return Optional.of(new KeyLength(keySize.getValue(), detectionLocation));
        } else if (value instanceof Curve<Tree> curve
                && detectionContext instanceof DetectionContext context
                && context.get("algorithm").map(a -> a.equalsIgnoreCase("EC")).orElse(false)) {
            final PycaCurveMapper mapper = new PycaCurveMapper();
            return mapper.parse(curve.asString(), detectionLocation)
                    .map(
                            ec -> {
                                PrivateKey privateKey = new PrivateKey((PublicKeyEncryption) ec);
                                privateKey.put(new KeyGeneration(detectionLocation));
                                // currently only GENERATE is
                                // used as key action is this
                                // context
                                return privateKey;
                            });
        }
        return Optional.empty();
    }

    private static @Nonnull Optional<INode> getPrivateKey(
            @Nonnull DetectionContext context,
            @Nullable Integer keySize,
            @Nonnull DetectionLocation detectionLocation) {
        final PycaKeyBasedAlgorithmMapper mapper = new PycaKeyBasedAlgorithmMapper();
        return context.get("algorithm")
                .flatMap(str -> mapper.parse(str, detectionLocation))
                .map(algorithm -> new PrivateKey(new Key(algorithm)))
                .map(
                        privateKey -> {
                            privateKey.put(new KeyGeneration(detectionLocation));
                            return privateKey;
                        })
                .map(
                        key -> {
                            if (keySize != null) {
                                key.put(new KeyLength(keySize, detectionLocation));
                            }
                            return key;
                        });
    }
}
