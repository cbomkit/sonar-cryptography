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
import com.ibm.engine.model.Mode;
import com.ibm.engine.model.OperationMode;
import com.ibm.engine.model.Padding;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.mapper.jca.JcaCipherOperationModeMapper;
import com.ibm.mapper.mapper.jca.JcaModeMapper;
import com.ibm.mapper.mapper.jca.JcaPaddingMapper;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.DES;
import com.ibm.mapper.model.algorithms.DESede;
import com.ibm.mapper.model.algorithms.RC2;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;

/** Translates {@link com.ibm.engine.model.context.CipherContext} detections for .NET APIs. */
public final class CSharpCipherContextTranslator
        implements IContextTranslation<com.ibm.engine.language.csharp.tree.CSharpTree> {

    private static final Logger LOG = Loggers.get(CSharpCipherContextTranslator.class);

    @Override
    public @Nonnull Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<com.ibm.engine.language.csharp.tree.CSharpTree> value,
            @Nonnull IDetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {

        if (value instanceof ValueAction<?>) {
            String valueStr = value.asString().toUpperCase().trim();
            Optional<INode> result =
                    switch (valueStr) {
                        case "AES" -> Optional.of(new AES(detectionLocation));
                        case "DES" -> Optional.of(new DES(detectionLocation));
                        case "3DES", "DESEDE", "TRIPLEDES" ->
                                Optional.of(new DESede(detectionLocation));
                        case "RSA" -> Optional.of(new RSA(detectionLocation));
                        case "RC2" -> Optional.of(new RC2(detectionLocation));
                        default -> Optional.empty();
                    };
            if (result.isPresent()) {
                return result;
            }
            // Try operation mode
            JcaCipherOperationModeMapper modeMapper = new JcaCipherOperationModeMapper();
            return modeMapper.parse(valueStr, detectionLocation).map(mode -> mode);
        } else if (value instanceof BlockSize<?> blockSize) {
            return Optional.of(
                    new com.ibm.mapper.model.BlockSize(blockSize.getValue(), detectionLocation));
        } else if (value instanceof KeySize<?> keySize) {
            return Optional.of(new KeyLength(keySize.getValue(), detectionLocation));
        } else if (value instanceof OperationMode<?> operationMode) {
            JcaCipherOperationModeMapper operationModeMapper = new JcaCipherOperationModeMapper();
            return operationModeMapper
                    .parse(operationMode.asString(), detectionLocation)
                    .map(f -> f);
        } else if (value instanceof Mode<?> mode) {
            // From set_Mode property setter: CipherMode.CBC → "CBC"
            JcaModeMapper modeMapper = new JcaModeMapper();
            return modeMapper.parse(mode.asString(), detectionLocation).map(m -> m);
        } else if (value instanceof Padding<?> padding) {
            // From set_Padding property setter: PaddingMode.PKCS7 → "PKCS7"
            JcaPaddingMapper paddingMapper = new JcaPaddingMapper();
            return paddingMapper.parse(padding.asString(), detectionLocation).map(p -> p);
        }

        return Optional.empty();
    }
}
