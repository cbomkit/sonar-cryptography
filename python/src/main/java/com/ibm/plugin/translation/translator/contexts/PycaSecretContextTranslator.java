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
import com.ibm.engine.model.context.DetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.SecretKey;
import com.ibm.mapper.model.algorithms.Fernet;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

public final class PycaSecretContextTranslator implements IContextTranslation<Tree> {
    @Override
    public @Nonnull Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<Tree> value,
            @Nonnull DetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {
        if (value instanceof KeyAction<Tree>) {
            // action is always "generate"
            return detectionContext
                    .get("algorithm")
                    .map(
                            str ->
                                    switch (str.toUpperCase().trim()) {
                                        case "FERNET" -> new Fernet(detectionLocation);
                                        default -> null;
                                    })
                    .map(
                            algo -> {
                                final SecretKey key = new SecretKey(algo);
                                key.put(new KeyGeneration(detectionLocation));
                                return key;
                            });
        }
        return Optional.empty();
    }
}
