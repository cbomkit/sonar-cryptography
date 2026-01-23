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
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.algorithms.DSA;
import com.ibm.mapper.model.algorithms.ECDSA;
import com.ibm.mapper.model.algorithms.Ed25519;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.mapper.model.functionality.Verify;
import com.ibm.mapper.utils.DetectionLocation;
import org.sonar.plugins.go.api.Tree;

import javax.annotation.Nonnull;
import java.util.Optional;

/**
 * Translator for Go Signature contexts.
 *
 * <p>Translates detected signature-related values to their corresponding mapper model classes.
 */
public final class GoSignatureContextTranslator implements IContextTranslation<Tree> {

    @Override
    public @Nonnull Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<Tree> value,
            @Nonnull IDetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {

        if (value instanceof ValueAction<Tree>) {
            String valueStr = value.asString().toUpperCase().trim();

            // RSA-related signature values
            if (valueStr.startsWith("RSA")) {
                return Optional.of(new RSA(Signature.class, detectionLocation));
            }

            // ECDSA
            if (valueStr.equals("ECDSA")) {
                return Optional.of(new ECDSA(detectionLocation));
            }

            // Ed25519
            if (valueStr.equals("ED25519")) {
                return Optional.of(new Ed25519(detectionLocation));
            }

            // DSA
            if (valueStr.equals("DSA")) {
                return Optional.of(new DSA(detectionLocation));
            }

            return Optional.empty();
        } else if (value instanceof SignatureAction<Tree> signatureAction) {
            switch (signatureAction.getAction()) {
                case SIGN:
                    return Optional.of(new Sign(detectionLocation));
                case VERIFY:
                    return Optional.of(new Verify(detectionLocation));
                default:
                    return Optional.empty();
            }
        }

        return Optional.empty();
    }
}
