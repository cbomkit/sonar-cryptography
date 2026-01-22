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
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.algorithms.MD5;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.algorithms.SHA3;
import com.ibm.mapper.model.algorithms.shake.SHAKE;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.sonar.plugins.go.api.Tree;

/**
 * Translator for Go digest/hash contexts.
 *
 * <p>Translates detected hash algorithm values to their corresponding mapper model classes.
 */
public final class GoDigestContextTranslator implements IContextTranslation<Tree> {

    @Override
    public @Nonnull Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<Tree> value,
            @Nonnull IDetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {

        if (value instanceof ValueAction<Tree>) {
            return switch (value.asString().toUpperCase().trim()) {
                case "MD5" -> Optional.of(new MD5(detectionLocation));
                case "SHA1" -> Optional.of(new SHA(detectionLocation));
                case "SHA224" -> Optional.of(new SHA2(224, detectionLocation));
                case "SHA256" -> Optional.of(new SHA2(256, detectionLocation));
                case "SHA384" -> Optional.of(new SHA2(384, detectionLocation));
                case "SHA512" -> Optional.of(new SHA2(512, detectionLocation));
                case "SHA3-224" -> Optional.of(new SHA3(224, detectionLocation));
                case "SHA3-256" -> Optional.of(new SHA3(256, detectionLocation));
                case "SHA3-384" -> Optional.of(new SHA3(384, detectionLocation));
                case "SHA3-512" -> Optional.of(new SHA3(512, detectionLocation));
                case "SHAKE128" -> Optional.of(new SHAKE(128, detectionLocation));
                case "SHAKE256" -> Optional.of(new SHAKE(256, detectionLocation));
                default -> Optional.empty();
            };
        }

        return Optional.empty();
    }
}
