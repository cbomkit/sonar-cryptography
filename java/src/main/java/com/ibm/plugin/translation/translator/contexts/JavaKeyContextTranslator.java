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
import com.ibm.engine.model.AlgorithmParameter;
import com.ibm.engine.model.Curve;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.OperationMode;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.DetectionContext;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.engine.model.context.PublicKeyContext;
import com.ibm.engine.model.context.SecretKeyContext;
import com.ibm.mapper.mapper.bc.BcAgreementMapper;
import com.ibm.mapper.mapper.bc.BcDerivationFunctionMapper;
import com.ibm.mapper.mapper.bc.BcKemMapper;
import com.ibm.mapper.mapper.bc.BcOperationModeKDFMapper;
import com.ibm.mapper.mapper.bc.BcParameterMapper;
import com.ibm.mapper.mapper.bc.BcPublicKeyEncryptionMapper;
import com.ibm.mapper.mapper.jca.JcaAlgorithmMapper;
import com.ibm.mapper.mapper.jca.JcaCurveMapper;
import com.ibm.mapper.model.IAlgorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Key;
import com.ibm.mapper.model.KeyDerivationFunction;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.PrivateKey;
import com.ibm.mapper.model.PublicKey;
import com.ibm.mapper.model.SecretKey;
import com.ibm.mapper.model.functionality.KeyDerivation;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

public final class JavaKeyContextTranslator extends JavaAbstractLibraryTranslator {

    @Override
    protected @Nonnull Optional<INode> translateJCA(
            @Nonnull IValue<Tree> value,
            @Nonnull DetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {
        if (value instanceof Algorithm<Tree> algorithm) {
            JcaAlgorithmMapper jcaAlgorithmMapper = new JcaAlgorithmMapper();
            return jcaAlgorithmMapper
                    .parse(algorithm.asString(), detectionLocation)
                    .map(
                            algo -> {
                                // Add appropriate functionality based on algorithm type
                                if (algo instanceof KeyDerivationFunction) {
                                    algo.put(new KeyDerivation(detectionLocation));
                                } else {
                                    algo.put(new KeyGeneration(detectionLocation));
                                }
                                // put key
                                final Key key = new Key((IAlgorithm) algo);
                                if (detectionContext.is(PrivateKeyContext.class)) {
                                    return new PrivateKey(key);
                                } else if (detectionContext.is(PublicKeyContext.class)) {
                                    return new PublicKey(key);
                                } else if (detectionContext.is(SecretKeyContext.class)) {
                                    return new SecretKey(key);
                                }
                                return key;
                            });
        } else if (value instanceof KeySize<Tree> keySize) {
            final KeyLength keyLength = new KeyLength(keySize.getValue(), detectionLocation);
            return Optional.of(keyLength);
        } else if (value instanceof Curve<Tree> curve) {
            final JcaCurveMapper jcaCurveMapper = new JcaCurveMapper();
            return jcaCurveMapper
                    .parse(curve.asString(), detectionLocation)
                    .map(
                            algo -> {
                                // key gen
                                algo.put(new KeyGeneration(detectionLocation));
                                return algo;
                            });
        } else if (value instanceof KeyAction<Tree> keyAction) {
            return switch (keyAction.getAction()) {
                case PRIVATE_KEY_GENERATION ->
                        Optional.of(
                                new KeyGeneration(
                                        KeyGeneration.Specification.PRIVATE_KEY,
                                        detectionLocation));
                case PUBLIC_KEY_GENERATION ->
                        Optional.of(
                                new KeyGeneration(
                                        KeyGeneration.Specification.PUBLIC_KEY, detectionLocation));
                case SECRET_KEY_GENERATION ->
                        Optional.of(
                                new KeyGeneration(
                                        KeyGeneration.Specification.SECRET_KEY, detectionLocation));
                default -> Optional.empty();
            };
        }
        return Optional.empty();
    }

    @Override
    protected @Nonnull Optional<INode> translateBC(
            @Nonnull IValue<Tree> value,
            @Nonnull DetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {
        if (value instanceof ValueAction<Tree> valueAction) {
            String kind = detectionContext.get("kind").orElse("");
            switch (kind) {
                case "DH":
                    BcAgreementMapper bcAgreementMapper = new BcAgreementMapper();
                    return bcAgreementMapper
                            .parse(valueAction.asString(), detectionLocation)
                            .map(f -> f);
                case "KDF":
                    BcDerivationFunctionMapper bcDerivationFunctionMapper =
                            new BcDerivationFunctionMapper();
                    return bcDerivationFunctionMapper
                            .parse(valueAction.asString(), detectionLocation)
                            .map(f -> f);
                case "KEM":
                    BcKemMapper bcKEMMapper = new BcKemMapper();
                    return bcKEMMapper.parse(valueAction.asString(), detectionLocation).map(f -> f);
                case "PKE":
                    BcPublicKeyEncryptionMapper bcPublicKeyEncryptionMapper =
                            new BcPublicKeyEncryptionMapper();
                    return bcPublicKeyEncryptionMapper
                            .parse(valueAction.asString(), detectionLocation)
                            .map(f -> f);
                default:
                    return Optional.empty();
            }
        } else if (value instanceof KeySize<Tree> keySize) {
            KeyLength keyLength = new KeyLength(keySize.getValue(), detectionLocation);
            return Optional.of(keyLength);
        } else if (value instanceof OperationMode<Tree> operationMode) {
            final BcOperationModeKDFMapper bcOperationModeKDFMapper =
                    new BcOperationModeKDFMapper();
            return bcOperationModeKDFMapper
                    .parse(operationMode.asString(), detectionLocation)
                    .map(f -> f);
        } else if (value instanceof AlgorithmParameter<Tree> algorithmParameter) {
            final BcParameterMapper bcParameterMapper = new BcParameterMapper();
            return bcParameterMapper
                    .parse(algorithmParameter.asString(), detectionLocation)
                    .map(f -> f);
        }
        return Optional.empty();
    }
}
