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
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.algorithms.DH;
import com.ibm.mapper.model.algorithms.ECDH;
import com.ibm.mapper.model.algorithms.MLKEM;
import com.ibm.mapper.model.algorithms.SM2;
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
 * Translator for C++ key agreement detection contexts.
 *
 * <p>This translator handles the translation of key agreement-related detection values (Diffie-
 * Hellman, ECDH, X25519/X448, ML-KEM, SM2) to the mapper model nodes.
 */
public final class CxxKeyAgreementContextTranslator implements IContextTranslation<AstNode> {

    @Override
    public @Nonnull Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<AstNode> value,
            @Nonnull IDetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {

        if (value instanceof ValueAction<AstNode> || value instanceof Algorithm<AstNode>) {
            return byName(value.asString(), detectionLocation);
        }

        return Optional.empty();
    }

    @Nonnull
    private Optional<INode> byName(
            @Nonnull String rawName, @Nonnull DetectionLocation detectionLocation) {
        String algorithmName = rawName.toUpperCase().trim();

        // DH (Diffie-Hellman)
        if (algorithmName.equals("DH")) {
            return Optional.of(new DH(KeyAgreement.class, detectionLocation));
        }
        if (algorithmName.equals("DH-2048")) {
            return Optional.of(new DH(KeyAgreement.class, detectionLocation));
        }
        if (algorithmName.equals("DH-3072")) {
            return Optional.of(new DH(KeyAgreement.class, detectionLocation));
        }
        if (algorithmName.equals("DH-4096")) {
            return Optional.of(new DH(KeyAgreement.class, detectionLocation));
        }

        // ECDH (Elliptic Curve Diffie-Hellman)
        if (algorithmName.equals("ECDH")) {
            return Optional.of(new ECDH(detectionLocation));
        }
        if (algorithmName.startsWith("ECDH-")) {
            // ECDH-P256, ECDH-P384, ECDH-P521, ECDH-SECP256K1
            return Optional.of(new ECDH(detectionLocation));
        }

        // X25519 and X448
        if (algorithmName.equals("X25519")) {
            return Optional.of(new X25519(detectionLocation));
        }
        if (algorithmName.equals("X448")) {
            return Optional.of(new X448(detectionLocation));
        }

        // ML-KEM (Kyber) - Post-Quantum Key Encapsulation Mechanism
        if (algorithmName.equals("ML-KEM-512")) {
            return Optional.of(new MLKEM(512, detectionLocation));
        }
        if (algorithmName.equals("ML-KEM-768")) {
            return Optional.of(new MLKEM(768, detectionLocation));
        }
        if (algorithmName.equals("ML-KEM-1024")) {
            return Optional.of(new MLKEM(1024, detectionLocation));
        }

        // Hybrid Post-Quantum KEMs (PQC + Classical)
        if (algorithmName.equals("X25519MLKEM768")) {
            return Optional.of(new X25519MLKEM768(detectionLocation));
        }
        if (algorithmName.equals("X448MLKEM1024")) {
            return Optional.of(new X448MLKEM1024(detectionLocation));
        }
        if (algorithmName.equals("SECP256R1MLKEM768")) {
            return Optional.of(new SecP256r1MLKEM768(detectionLocation));
        }
        if (algorithmName.equals("SECP384R1MLKEM1024")) {
            return Optional.of(new SecP384r1MLKEM1024(detectionLocation));
        }

        // SM2 Key Exchange
        if (algorithmName.equals("SM2")) {
            return Optional.of(new SM2(detectionLocation));
        }

        return Optional.empty();
    }
}
