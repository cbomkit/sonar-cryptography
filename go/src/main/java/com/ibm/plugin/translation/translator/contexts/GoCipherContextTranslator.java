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

import com.ibm.engine.model.BlockSize;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.OperationMode;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.mapper.gocrypto.GoCryptoModeMapper;
import com.ibm.mapper.mapper.jca.JcaCipherOperationModeMapper;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.DES;
import com.ibm.mapper.model.algorithms.DESede;
import com.ibm.mapper.model.algorithms.RC4;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.sonar.plugins.go.api.Tree;

public final class GoCipherContextTranslator implements IContextTranslation<Tree> {

    @Override
    public @Nonnull Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<Tree> value,
            @Nonnull IDetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {

        if (value instanceof ValueAction<Tree>) {
            String valueStr = value.asString().toUpperCase().trim();
            // Try to map as algorithm first
            Optional<INode> algorithmResult =
                    switch (valueStr) {
                        case "AES" -> Optional.of(new AES(detectionLocation));
                        case "DES" -> Optional.of(new DES(detectionLocation));
                        case "3DES", "DESEDE", "TRIPLEDES" ->
                                Optional.of(new DESede(detectionLocation));
                        case "RC4", "ARC4", "ARCFOUR" -> Optional.of(new RC4(detectionLocation));
                        default -> Optional.empty();
                    };
            if (algorithmResult.isPresent()) {
                return algorithmResult;
            }
            // Try to map as cipher mode
            GoCryptoModeMapper modeMapper = new GoCryptoModeMapper();
            return modeMapper.parse(valueStr, detectionLocation).map(mode -> mode);
        } else if (value instanceof BlockSize<Tree> blockSize) {
            return Optional.of(
                    new com.ibm.mapper.model.BlockSize(blockSize.getValue(), detectionLocation));
        } else if (value instanceof KeySize<Tree> keySize) {
            final KeyLength keyLength = new KeyLength(keySize.getValue(), detectionLocation);
            return Optional.of(keyLength);
        } else if (value instanceof OperationMode<Tree> operationMode) {
            JcaCipherOperationModeMapper operationModeMapper = new JcaCipherOperationModeMapper();
            return operationModeMapper
                    .parse(operationMode.asString(), detectionLocation)
                    .map(f -> f);
        }

        return Optional.empty();
    }
}
