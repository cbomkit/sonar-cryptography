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
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.DetectionContext;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.mapper.gocrypto.GoCryptoCurveMapper;
import com.ibm.mapper.mapper.gocrypto.GoCryptoKeyDerivationFunctionMapper;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.algorithms.DSA;
import com.ibm.mapper.model.algorithms.ECDH;
import com.ibm.mapper.model.algorithms.ECDSA;
import com.ibm.mapper.model.algorithms.Ed25519;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.functionality.Generate;
import com.ibm.mapper.utils.DetectionLocation;
import org.sonar.plugins.go.api.Tree;

import javax.annotation.Nonnull;
import java.util.Optional;

/**
 * Translator for Go Key contexts.
 *
 * <p>Translates detected key-related values to their corresponding mapper model classes.
 */
public final class GoKeyContextTranslator implements IContextTranslation<Tree> {

    @Override
    public @Nonnull Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<Tree> value,
            @Nonnull IDetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {
        if (value instanceof ValueAction<Tree>
                && detectionContext instanceof DetectionContext context) {
            final GoCryptoCurveMapper curveMapper = new GoCryptoCurveMapper();

            String kind = context.get("kind").orElse("");
            switch (kind) {
                case "RSA":
                    return Optional.of(new RSA(PublicKeyEncryption.class, detectionLocation));
                case "ECDSA":
                    return Optional.of(new ECDSA(detectionLocation));
                case "Ed25519":
                    return Optional.of(new Ed25519(detectionLocation));
                case "DSA":
                    return Optional.of(new DSA(detectionLocation));
                case "ECDH":
                    // Try to parse as curve name first (e.g., "P256", "X25519")
                    Optional<? extends INode> curveResult =
                            curveMapper.parse(value.asString(), detectionLocation).map(ECDH::new);
                    if (curveResult.isPresent()) {
                        return curveResult.map(n -> n);
                    }
                    // If value is "ECDH" itself (from GenerateKey/NewPrivateKey/NewPublicKey),
                    // return a generic ECDH node without curve details
                    if ("ECDH".equals(value.asString())) {
                        return Optional.of(new ECDH(detectionLocation));
                    }
                    return Optional.empty();
                case "EC":
                    return curveMapper.parse(value.asString(), detectionLocation).map(f -> f);
                case "KDF":
                    final GoCryptoKeyDerivationFunctionMapper kdfMapper =
                            new GoCryptoKeyDerivationFunctionMapper();
                    return kdfMapper.parse(value.asString(), detectionLocation).map(n -> n);
                default:
                    return Optional.empty();
            }
        } else if (value instanceof KeySize<Tree> keySize) {
            return Optional.of(new KeyLength(keySize.getValue(), detectionLocation));
        } else if (value instanceof KeyAction<Tree> keyAction) {
            switch (keyAction.getAction()) {
                case PRIVATE_KEY_GENERATION, PUBLIC_KEY_GENERATION, SECRET_KEY_GENERATION:
                    return Optional.of(new Generate(detectionLocation));
                default:
                    return Optional.empty();
            }
        }

        return Optional.empty();
    }
}
