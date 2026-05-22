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
import com.ibm.engine.model.context.DetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.SecretKey;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.ChaCha20Poly1305;
import com.ibm.mapper.model.functionality.Encapsulate;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.mapper.model.mode.CCM;
import com.ibm.mapper.model.mode.GCM;
import com.ibm.mapper.model.mode.GCMSIV;
import com.ibm.mapper.model.mode.OCB;
import com.ibm.mapper.model.mode.SIV;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

public final class PycaSecretKeyContextTranslator implements IContextTranslation<Tree> {

    @Override
    public @Nonnull Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<Tree> value,
            @Nonnull DetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {
        if (value instanceof KeySize<Tree> keySize
                && detectionContext.get("kind").map(k -> k.equals("AEAD")).orElse(false)) {
            return detectionContext.get("algorithm")
                    .map(
                            str ->
                                    switch (str.toUpperCase().trim()) {
                                        case "AESGCM" ->
                                                new AES(
                                                        keySize.getValue(),
                                                        new GCM(detectionLocation),
                                                        detectionLocation);
                                        case "AESGCMIV" ->
                                                new AES(
                                                        keySize.getValue(),
                                                        new GCMSIV(detectionLocation),
                                                        detectionLocation);
                                        case "AESOCB3" ->
                                                new AES(
                                                        keySize.getValue(),
                                                        new OCB(3, detectionLocation),
                                                        detectionLocation);
                                        case "AESSIV" ->
                                                new AES(
                                                        keySize.getValue(),
                                                        new SIV(detectionLocation),
                                                        detectionLocation);
                                        case "AESCCM" ->
                                                new AES(
                                                        keySize.getValue(),
                                                        new CCM(detectionLocation),
                                                        detectionLocation);
                                        default -> null;
                                    })
                    .map(SecretKey::new)
                    .map(
                            key -> {
                                key.put(new KeyGeneration(detectionLocation));
                                return key;
                            });
        } else if (value instanceof KeyAction<Tree> keyAction
                && detectionContext.get("kind").map(k -> k.equals("AEAD")).orElse(false)) {
            return detectionContext.get("algorithm")
                    .map(
                            str ->
                                    switch (str.toUpperCase().trim()) {
                                        case "CHACHA20POLY1305" ->
                                                new ChaCha20Poly1305(detectionLocation);
                                        default -> null;
                                    })
                    .map(SecretKey::new)
                    .map(
                            key -> {
                                switch (keyAction.getAction()) {
                                    case GENERATION ->
                                            key.put(new KeyGeneration(detectionLocation));
                                    case KDF -> key.put(new Encapsulate(detectionLocation));
                                }
                                return key;
                            });
        }

        return Optional.empty();
    }
}
