/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2024 IBM
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
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
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.DetectionContext;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.mapper.jca.JcaMessageDigestMapper;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.algorithms.HKDF;
import com.ibm.mapper.model.algorithms.PBKDF2;
import com.ibm.mapper.model.algorithms.Scrypt;
import com.ibm.mapper.model.functionality.KeyDerivation;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.plugin.javascript.api.Tree;
import java.util.Optional;
import javax.annotation.Nonnull;

public final class JavaScriptKeyDerivationContextTranslator implements IContextTranslation<Tree> {

    @Override
    public @Nonnull Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<Tree> value,
            @Nonnull IDetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {
        if (value instanceof Algorithm<Tree> algorithm
                && detectionContext instanceof DetectionContext context) {
            Optional<String> possibleKind = context.get("kind");
            if (possibleKind.isPresent()) {
                JcaMessageDigestMapper digestMapper = new JcaMessageDigestMapper();
                return switch (possibleKind.get()) {
                    case "hkdf" ->
                            digestMapper
                                    .parse(algorithm.asString(), detectionLocation)
                                    .map(
                                            digest -> {
                                                HKDF hkdf = new HKDF(digest);
                                                hkdf.put(new KeyDerivation(detectionLocation));
                                                return hkdf;
                                            });
                    case "pbkdf2" ->
                            digestMapper
                                    .parse(algorithm.asString(), detectionLocation)
                                    .map(
                                            digest -> {
                                                PBKDF2 pbkdf2 = new PBKDF2(digest);
                                                pbkdf2.put(new KeyDerivation(detectionLocation));
                                                return pbkdf2;
                                            });
                    default -> Optional.empty();
                };
            }
        } else if (value instanceof ValueAction<Tree> action) {
            if ("SCRYPT".equalsIgnoreCase(action.asString().trim())) {
                Scrypt scrypt = new Scrypt(detectionLocation);
                scrypt.put(new KeyDerivation(detectionLocation));
                return Optional.of(scrypt);
            }
        } else if (value instanceof KeySize<Tree> keySize) {
            return Optional.of(new KeyLength(keySize.getValue(), detectionLocation));
        }
        return Optional.empty();
    }
}
