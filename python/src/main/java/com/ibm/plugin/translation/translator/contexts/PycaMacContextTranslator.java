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
import com.ibm.engine.model.context.DetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.mapper.pyca.PycaCipherMapper;
import com.ibm.mapper.mapper.pyca.PycaDigestMapper;
import com.ibm.mapper.model.Cipher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.algorithms.CMAC;
import com.ibm.mapper.model.algorithms.HMAC;
import com.ibm.mapper.model.algorithms.Poly1305;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

@SuppressWarnings("java:S1301")
public final class PycaMacContextTranslator implements IContextTranslation<Tree> {

    @Override
    public @Nonnull Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<Tree> value,
            @Nonnull DetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {

        if (value instanceof com.ibm.engine.model.Algorithm<Tree> algorithm) {
            // hash algorithm
            Optional<String> possibleKind = detectionContext.get("kind");
            if (possibleKind.isPresent()) {
                final String kind = possibleKind.get();
                return switch (kind) {
                    case "cmac" -> {
                        final PycaCipherMapper cipherMapper = new PycaCipherMapper();
                        yield cipherMapper
                                .parse(algorithm.asString(), detectionLocation)
                                .map(
                                        c -> {
                                            if (c instanceof Cipher cipher) {
                                                return new CMAC(cipher);
                                            }
                                            return null;
                                        });
                    }
                    case "hmac" -> {
                        final PycaDigestMapper digestMapper = new PycaDigestMapper();
                        yield digestMapper
                                .parse(algorithm.asString(), detectionLocation)
                                .map(HMAC::new);
                    }
                    default -> Optional.empty();
                };
            }
        } else if (value instanceof ValueAction<Tree> action) {
            if (action.asString().equalsIgnoreCase("poly1305")) {
                return Optional.of(new HMAC(new Poly1305(detectionLocation)));
            }
        }
        return Optional.empty();
    }
}
