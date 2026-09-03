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

import com.ibm.engine.model.AlgorithmParameter;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.IterationCount;
import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.SaltSize;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.DetectionContext;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.mapper.gocrypto.GoCryptoCurveMapper;
import com.ibm.mapper.mapper.gocrypto.GoCryptoDSAParameterMapper;
import com.ibm.mapper.mapper.gocrypto.GoCryptoKEMMapper;
import com.ibm.mapper.mapper.gocrypto.GoCryptoKeyDerivationFunctionMapper;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Key;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.NumberOfIterations;
import com.ibm.mapper.model.PrivateKey;
import com.ibm.mapper.model.PublicKey;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.SaltLength;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.Unknown;
import com.ibm.mapper.model.algorithms.DSA;
import com.ibm.mapper.model.algorithms.ECDH;
import com.ibm.mapper.model.algorithms.ECDSA;
import com.ibm.mapper.model.algorithms.Ed25519;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.Certificate;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.engine.model.context.PublicKeyContext;
import com.ibm.engine.model.context.CertificateContext;
import com.ibm.mapper.model.functionality.Decapsulate;
import com.ibm.mapper.model.functionality.Encapsulate;
import com.ibm.mapper.model.functionality.Generate;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.sonar.plugins.go.api.Tree;

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
            
            if (context instanceof CertificateContext) {
                 String format = context.get("format").orElse("X.509");
                 return Optional.of(new Certificate(format, detectionLocation));
            }

            final GoCryptoCurveMapper curveMapper = new GoCryptoCurveMapper();

            String kind = context.get("kind").orElse("");
            INode algorithmNode = null;
            switch (kind) {
                case "RSA":
                    algorithmNode = new RSA(PublicKeyEncryption.class, detectionLocation);
                    break;
                case "ECDSA":
                    algorithmNode = new ECDSA(detectionLocation);
                    break;
                case "Ed25519":
                    algorithmNode = new Ed25519(detectionLocation);
                    break;
                case "DSA":
                    algorithmNode = new DSA(detectionLocation);
                    break;
                case "ECDH":
                    // Try to parse as curve name first (e.g., "P256", "X25519")
                    Optional<? extends INode> curveResult =
                            curveMapper.parse(value.asString(), detectionLocation).map(ECDH::new);
                    if (curveResult.isPresent()) {
                        algorithmNode = curveResult.get();
                    } else if ("ECDH".equals(value.asString())) {
                        algorithmNode = new ECDH(detectionLocation);
                    }
                    break;
                case "PKCS1":
                    algorithmNode = new RSA(detectionLocation);
                    break;
                case "PKCS8":
                case "X509":
                    algorithmNode = new Unknown(detectionLocation);
                    break;
                case "EC":
                    Optional<? extends INode> parsed = curveMapper.parse(value.asString(), detectionLocation);
                    if (parsed.isPresent()) {
                        algorithmNode = parsed.get();
                    }
                    break;
                case "KDF":
                    final GoCryptoKeyDerivationFunctionMapper kdfMapper =
                            new GoCryptoKeyDerivationFunctionMapper();
                    return kdfMapper.parse(value.asString(), detectionLocation).map(n -> n);
                case "KEM":
                    final GoCryptoKEMMapper kemMapper = new GoCryptoKEMMapper();
                    return kemMapper.parse(value.asString(), detectionLocation).map(n -> n);
                default:
                    return Optional.empty();
            }

            if (algorithmNode != null) {
                if (context instanceof PrivateKeyContext) {
                    if (algorithmNode instanceof PublicKeyEncryption pke) {
                        return Optional.of(new PrivateKey(pke));
                    } else if (algorithmNode instanceof Signature sig) {
                        return Optional.of(new PrivateKey(sig));
                    } else if (algorithmNode instanceof Key key) {
                        return Optional.of(new PrivateKey(key));
                    }
                } else if (context instanceof PublicKeyContext) {
                    if (algorithmNode instanceof PublicKeyEncryption pke) {
                        return Optional.of(new PublicKey(pke));
                    } else if (algorithmNode instanceof Signature sig) {
                        return Optional.of(new PublicKey(sig));
                    } else if (algorithmNode instanceof Key key) {
                        return Optional.of(new PublicKey(key));
                    }
                }
                return Optional.of(algorithmNode);
            }
        } else if (value instanceof KeySize<Tree> keySize) {
            return Optional.of(new KeyLength(keySize.getValue(), detectionLocation));
        } else if (value instanceof KeyAction<Tree> keyAction) {
            switch (keyAction.getAction()) {
                case PRIVATE_KEY_GENERATION, PUBLIC_KEY_GENERATION, SECRET_KEY_GENERATION:
                    return Optional.of(new Generate(detectionLocation));
                case ENCAPSULATION:
                    return Optional.of(new Encapsulate(detectionLocation));
                case DECAPSULATION:
                    return Optional.of(new Decapsulate(detectionLocation));
                default:
                    return Optional.empty();
            }
        } else if (value instanceof AlgorithmParameter<Tree> algorithmParameter) {
            switch (algorithmParameter.getKind()) {
                case DSA_L_AND_N:
                    final GoCryptoDSAParameterMapper dsaParameterMapper =
                            new GoCryptoDSAParameterMapper();
                    return dsaParameterMapper
                            .parse(algorithmParameter.asString(), detectionLocation)
                            .map(n -> n);
                default:
                    return Optional.empty();
            }
        } else if (value instanceof SaltSize<Tree> saltSize) {
            return Optional.of(new SaltLength(saltSize.getValue(), detectionLocation));
        } else if (value instanceof IterationCount<Tree> iterationCount) {
            return Optional.of(
                    new NumberOfIterations(iterationCount.getValue(), detectionLocation));
        }
        return Optional.empty();
    }
}
