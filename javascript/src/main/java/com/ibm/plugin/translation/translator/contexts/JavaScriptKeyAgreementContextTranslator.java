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
import com.ibm.engine.model.Curve;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.DetectionContext;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.mapper.gocrypto.GoCryptoCurveMapper;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.algorithms.DH;
import com.ibm.mapper.model.algorithms.ECDH;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.plugin.javascript.api.Tree;
import java.util.Optional;
import javax.annotation.Nonnull;

public final class JavaScriptKeyAgreementContextTranslator implements IContextTranslation<Tree> {

    @Override
    public @Nonnull Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<Tree> value,
            @Nonnull IDetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {
        if (value instanceof Algorithm<Tree> algorithm) {
            return mapAlgorithm(algorithm.asString(), detectionLocation);
        } else if (value instanceof ValueAction<Tree>
                && detectionContext instanceof DetectionContext context) {
            return context.get("algorithm").flatMap(algo -> mapAlgorithm(algo, detectionLocation));
        } else if (value instanceof KeyAction<Tree>
                && detectionContext instanceof DetectionContext context) {
            return context.get("algorithm").flatMap(algo -> mapAlgorithm(algo, detectionLocation));
        } else if (value instanceof Curve<Tree> curve) {
            GoCryptoCurveMapper curveMapper = new GoCryptoCurveMapper();
            return curveMapper
                    .parse(curve.asString(), detectionLocation)
                    .map(node -> new ECDH(detectionLocation))
                    .map(ka -> withKeyGeneration(ka, detectionLocation));
        }
        return Optional.empty();
    }

    @Nonnull
    private Optional<INode> mapAlgorithm(
            @Nonnull String algo, @Nonnull DetectionLocation location) {
        return Optional.of(algo.toUpperCase().trim())
                .map(
                        normalized ->
                                switch (normalized) {
                                    case "DH" -> new DH(location);
                                    case "ECDH", "X25519", "X448" -> new ECDH(location);
                                    default -> null;
                                })
                .map(ka -> withKeyGeneration(ka, location));
    }

    @Nonnull
    private INode withKeyGeneration(
            @Nonnull INode ka, @Nonnull DetectionLocation detectionLocation) {
        ka.put(new KeyGeneration(detectionLocation));
        return ka;
    }
}
