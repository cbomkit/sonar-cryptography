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
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.model.EllipticCurveAlgorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.PrivateKey;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.algorithms.DH;
import com.ibm.mapper.model.algorithms.DSA;
import com.ibm.mapper.model.algorithms.Ed25519;
import com.ibm.mapper.model.algorithms.Ed448;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.curves.Brainpoolp256r1;
import com.ibm.mapper.model.curves.Brainpoolp384r1;
import com.ibm.mapper.model.curves.Brainpoolp512r1;
import com.ibm.mapper.model.curves.Secp192r1;
import com.ibm.mapper.model.curves.Secp224r1;
import com.ibm.mapper.model.curves.Secp256k1;
import com.ibm.mapper.model.curves.Secp256r1;
import com.ibm.mapper.model.curves.Secp384r1;
import com.ibm.mapper.model.curves.Secp521r1;
import com.ibm.mapper.model.curves.Sect163k1;
import com.ibm.mapper.model.curves.Sect163r2;
import com.ibm.mapper.model.curves.Sect233k1;
import com.ibm.mapper.model.curves.Sect233r1;
import com.ibm.mapper.model.curves.Sect283k1;
import com.ibm.mapper.model.curves.Sect283r1;
import com.ibm.mapper.model.curves.Sect409k1;
import com.ibm.mapper.model.curves.Sect409r1;
import com.ibm.mapper.model.curves.Sect571k1;
import com.ibm.mapper.model.curves.Sect571r1;
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
            @Nonnull DetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {
        if (value instanceof KeyAction<Tree>) {
            return getPrivateKey(detectionContext, null, detectionLocation);
        } else if (value instanceof KeySize<Tree> keySize) {
            if (detectionContext.get("algorithm").isPresent()) {
                return getPrivateKey(detectionContext, keySize.getValue(), detectionLocation);
            }
            return Optional.of(new KeyLength(keySize.getValue(), detectionLocation));
        } else if (value instanceof Curve<Tree> curve
                && detectionContext
                        .get("algorithm")
                        .map(a -> a.equalsIgnoreCase("EC"))
                        .orElse(false)) {
            return Optional.of(curve.asString())
                    .map(
                            str ->
                                    switch (str.toUpperCase().trim()) {
                                        case "SECP256R1" -> new Secp256r1(detectionLocation);
                                        case "SECP384R1" -> new Secp384r1(detectionLocation);
                                        case "SECP521R1" -> new Secp521r1(detectionLocation);
                                        case "SECP224R1" -> new Secp224r1(detectionLocation);
                                        case "SECP192R1" -> new Secp192r1(detectionLocation);
                                        case "SECP256K1" -> new Secp256k1(detectionLocation);
                                        case "BRAINPOOLP256R1" ->
                                                new Brainpoolp256r1(detectionLocation);
                                        case "BRAINPOOLP384R1" ->
                                                new Brainpoolp384r1(detectionLocation);
                                        case "BRAINPOOLP512R1" ->
                                                new Brainpoolp512r1(detectionLocation);
                                        case "SECT571K1" -> new Sect571k1(detectionLocation);
                                        case "SECT409K1" -> new Sect409k1(detectionLocation);
                                        case "SECT283K1" -> new Sect283k1(detectionLocation);
                                        case "SECT233K1" -> new Sect233k1(detectionLocation);
                                        case "SECT163K1" -> new Sect163k1(detectionLocation);
                                        case "SECT571R1" -> new Sect571r1(detectionLocation);
                                        case "SECT409R1" -> new Sect409r1(detectionLocation);
                                        case "SECT283R1" -> new Sect283r1(detectionLocation);
                                        case "SECT233R1" -> new Sect233r1(detectionLocation);
                                        case "SECT163R2" -> new Sect163r2(detectionLocation);
                                        default -> null;
                                    })
                    .map(EllipticCurveAlgorithm::new)
                    .map(
                            ec -> {
                                PrivateKey privateKey = new PrivateKey((PublicKeyEncryption) ec);
                                privateKey.put(
                                        new KeyGeneration(
                                                detectionLocation)); // currently only GENERATE is
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
        return context.get("algorithm")
                .map(
                        str ->
                                switch (str.toUpperCase().trim()) {
                                    case "DH" -> new DH(detectionLocation);
                                    case "RSA" -> new RSA(detectionLocation);
                                    case "DSA" -> new DSA(detectionLocation);
                                    case "EC" -> new EllipticCurveAlgorithm(detectionLocation);
                                    case "ED25519" -> new Ed25519(detectionLocation);
                                    case "ED448" -> new Ed448(detectionLocation);
                                    default -> null;
                                })
                .map(
                        algorithm -> {
                            PrivateKey privateKey = new PrivateKey(algorithm);
                            privateKey.put(
                                    new KeyGeneration(
                                            detectionLocation)); // currently only GENERATE is
                            // used as key action is this
                            // context
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
