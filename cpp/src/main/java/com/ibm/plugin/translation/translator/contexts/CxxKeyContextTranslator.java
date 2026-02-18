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
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.algorithms.DH;
import com.ibm.mapper.model.algorithms.DSA;
import com.ibm.mapper.model.algorithms.ECDSA;
import com.ibm.mapper.model.algorithms.Ed25519;
import com.ibm.mapper.model.algorithms.Ed448;
import com.ibm.mapper.model.algorithms.MLDSA;
import com.ibm.mapper.model.algorithms.MLKEM;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.SLHDSA;
import com.ibm.mapper.model.algorithms.SecP256r1MLKEM768;
import com.ibm.mapper.model.algorithms.SecP384r1MLKEM1024;
import com.ibm.mapper.model.algorithms.X25519;
import com.ibm.mapper.model.algorithms.X25519MLKEM768;
import com.ibm.mapper.model.algorithms.X448;
import com.ibm.mapper.model.algorithms.X448MLKEM1024;
import com.ibm.mapper.utils.DetectionLocation;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Translator for C++ key detection contexts.
 *
 * <p>This translator handles the translation of key-related detection values (public keys, private
 * keys, secret keys) to the mapper model nodes.
 */
public final class CxxKeyContextTranslator implements IContextTranslation<AstNode> {

    @Override
    public @Nonnull Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<AstNode> value,
            @Nonnull IDetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {

        if (value instanceof ValueAction<AstNode>) {
            return switch (value.asString().toUpperCase().trim()) {
                // RSA
                case "RSA" -> Optional.of(new RSA(detectionLocation));
                case "RSA-PSS" -> Optional.of(new RSA(detectionLocation));
                case "RSA-2048" -> Optional.of(new RSA(2048, detectionLocation));
                case "RSA-3072" -> Optional.of(new RSA(3072, detectionLocation));
                case "RSA-4096" -> Optional.of(new RSA(4096, detectionLocation));

                // DSA
                case "DSA" -> Optional.of(new DSA(detectionLocation));
                case "DSA-2048" -> Optional.of(new DSA(detectionLocation));
                case "DSA-3072" -> Optional.of(new DSA(detectionLocation));

                // EC
                case "EC" -> Optional.of(new ECDSA(detectionLocation));
                case "EC-P256" -> Optional.of(new ECDSA(detectionLocation));
                case "EC-P384" -> Optional.of(new ECDSA(detectionLocation));
                case "EC-P521" -> Optional.of(new ECDSA(detectionLocation));
                case "EC-SECP256K1" -> Optional.of(new ECDSA(detectionLocation));
                case "EC-BRAINPOOLP256R1" -> Optional.of(new ECDSA(detectionLocation));
                case "EC-BRAINPOOLP384R1" -> Optional.of(new ECDSA(detectionLocation));
                case "EC-BRAINPOOLP512R1" -> Optional.of(new ECDSA(detectionLocation));

                // DH
                case "DH" -> Optional.of(new DH(detectionLocation));
                case "DH-2048" -> Optional.of(new DH(PublicKeyEncryption.class, detectionLocation));
                case "DH-4096" -> Optional.of(new DH(PublicKeyEncryption.class, detectionLocation));

                // EdDSA
                case "ED25519" -> Optional.of(new Ed25519(detectionLocation));
                case "ED448" -> Optional.of(new Ed448(detectionLocation));

                // X25519/X448
                case "X25519" -> Optional.of(new X25519(detectionLocation));
                case "X448" -> Optional.of(new X448(detectionLocation));

                // ML-KEM (Post-Quantum)
                case "ML-KEM-512" -> Optional.of(new MLKEM(512, detectionLocation));
                case "ML-KEM-768" -> Optional.of(new MLKEM(768, detectionLocation));
                case "ML-KEM-1024" -> Optional.of(new MLKEM(1024, detectionLocation));

                // ML-DSA (Post-Quantum)
                case "ML-DSA-44" -> Optional.of(new MLDSA(2, detectionLocation));
                case "ML-DSA-65" -> Optional.of(new MLDSA(3, detectionLocation));
                case "ML-DSA-87" -> Optional.of(new MLDSA(5, detectionLocation));

                // SLH-DSA (Post-Quantum)
                case "SLH-DSA-SHA2-128F",
                        "SLH-DSA-SHA2-128S",
                        "SLH-DSA-SHAKE-128F",
                        "SLH-DSA-SHAKE-128S",
                        "SLH-DSA-SHA2-192F",
                        "SLH-DSA-SHA2-192S",
                        "SLH-DSA-SHAKE-192F",
                        "SLH-DSA-SHAKE-192S",
                        "SLH-DSA-SHA2-256F",
                        "SLH-DSA-SHA2-256S",
                        "SLH-DSA-SHAKE-256F",
                        "SLH-DSA-SHAKE-256S" ->
                        Optional.of(new SLHDSA(detectionLocation));

                // Hybrid Post-Quantum KEMs (PQC + Classical)
                case "X25519MLKEM768" -> Optional.of(new X25519MLKEM768(detectionLocation));
                case "X448MLKEM1024" -> Optional.of(new X448MLKEM1024(detectionLocation));
                case "SECP256R1MLKEM768" -> Optional.of(new SecP256r1MLKEM768(detectionLocation));
                case "SECP384R1MLKEM1024" -> Optional.of(new SecP384r1MLKEM1024(detectionLocation));

                // SM2
                case "SM2" ->
                        Optional.of(new com.ibm.mapper.model.algorithms.SM2(detectionLocation));

                default -> Optional.empty();
            };
        }

        return Optional.empty();
    }
}
