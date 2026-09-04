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
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.DetectionContext;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.mapper.jca.JcaMessageDigestMapper;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.algorithms.HMAC;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.plugin.javascript.api.Tree;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Translator for JavaScript MAC (Message Authentication Code) contexts.
 *
 * <p>Translates detected MAC algorithm values to their corresponding mapper model classes.
 * Currently supports HMAC detection from the crypto/hmac package.
 */
public final class JavaScriptMacContextTranslator implements IContextTranslation<Tree> {

    @Override
    public @Nonnull Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<Tree> value,
            @Nonnull IDetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {

        if (value instanceof Algorithm<Tree> algorithm
                && detectionContext instanceof DetectionContext context) {
            Optional<String> possibleKind = context.get("kind");
            if (possibleKind.isPresent() && "hmac".equalsIgnoreCase(possibleKind.get())) {
                JcaMessageDigestMapper digestMapper = new JcaMessageDigestMapper();
                return digestMapper.parse(algorithm.asString(), detectionLocation).map(HMAC::new);
            }
        }

        return Optional.empty();
    }
}
