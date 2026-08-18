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
import com.ibm.engine.model.SignatureAction;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.DetectionContext;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.model.EllipticCurveAlgorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.ProbabilisticSignatureScheme;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.algorithms.DSS;
import com.ibm.mapper.model.algorithms.ECDSA;
import com.ibm.mapper.model.algorithms.EdDSA;
import com.ibm.mapper.model.algorithms.MGF1;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.RSAssaPSS;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.mapper.model.functionality.Verify;
import com.ibm.mapper.model.padding.PKCS1;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

@SuppressWarnings("java:S1301")
public final class PycaSignatureContextTranslator implements IContextTranslation<Tree> {

    @Override
    public @Nonnull Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<Tree> value,
            @Nonnull IDetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {
        if (value instanceof com.ibm.engine.model.Algorithm<Tree> algorithm) {
            return switch (algorithm.asString().toUpperCase().trim()) {
                case "EC" ->
                        Optional.of(
                                new EllipticCurveAlgorithm(
                                        Signature.class,
                                        new EllipticCurveAlgorithm(detectionLocation)));
                case "ECDSA" -> Optional.of(new ECDSA(detectionLocation));
                case "RSA" -> {
                    if (detectionContext instanceof DetectionContext context
                            && context.get("kind").map(k -> k.equals("PSS")).orElse(false)) {
                        yield Optional.of(
                                new RSA(ProbabilisticSignatureScheme.class, detectionLocation));
                    }
                    yield Optional.of(new RSA(Signature.class, detectionLocation));
                }
                default -> Optional.empty();
            };
        } else if (value instanceof SignatureAction<Tree> signatureAction) {
            return switch (signatureAction.getAction()) {
                case SIGN -> Optional.of(new Sign(detectionLocation));
                case VERIFY -> Optional.of(new Verify(detectionLocation));
            };
        } else if (value instanceof ValueAction<Tree>
                && detectionContext instanceof DetectionContext context) {
            if (context.get("kind").map(k -> k.equals("padding")).orElse(false)) { // padding case
                return switch (value.asString().toUpperCase().trim()) {
                    case "PKCS1V15" -> Optional.empty(); // TODO
                    default -> Optional.empty();
                };
            } else {
                return switch (value.asString().toUpperCase().trim()) {
                    case "RSA" -> Optional.of(new RSA(Signature.class, detectionLocation));
                    case "DSS" -> Optional.of(new DSS(detectionLocation));
                    case "ECDSA" -> Optional.of(new ECDSA(detectionLocation));
                    case "EDDSA" -> Optional.of(new EdDSA(detectionLocation));
                    case "MGF1" -> Optional.of(new MGF1(detectionLocation));
                    case "RSA-PKCS1V15" -> {
                        RSA rsaPkcs1 = new RSA(Signature.class, detectionLocation);
                        rsaPkcs1.put(new PKCS1(detectionLocation));
                        yield Optional.of((INode) rsaPkcs1);
                    }
                    case "RSA-PSS" -> Optional.of(new RSAssaPSS(detectionLocation));
                    default -> Optional.empty();
                };
            }
        }
        return Optional.empty();
    }
}
