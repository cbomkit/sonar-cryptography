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
import com.ibm.engine.model.InitializationVectorSize;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.MacSize;
import com.ibm.engine.model.Mode;
import com.ibm.engine.model.TagSize;
import com.ibm.engine.model.context.DetectionContext;
import com.ibm.mapper.mapper.jca.JcaAlgorithmMapper;
import com.ibm.mapper.mapper.jca.JcaModeMapper;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.InitializationVectorLength;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.TagLength;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

public final class JavaAlgorithmParameterContextTranslator extends JavaAbstractLibraryTranslator {

    @Override
    protected @Nonnull Optional<INode> translateJCA(
            @Nonnull IValue<Tree> value,
            @Nonnull DetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {
        if (value instanceof Algorithm<Tree>) {
            JcaAlgorithmMapper jcaAlgorithmMapper = new JcaAlgorithmMapper();
            return jcaAlgorithmMapper.parse(value.asString(), detectionLocation).map(a -> a);
        }
        return translateCommon(value, detectionContext, detectionLocation);
    }

    @Nonnull
    protected Optional<INode> translateBC(
            @Nonnull IValue<Tree> value,
            @Nonnull DetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {
        return translateCommon(value, detectionContext, detectionLocation);
    }

    private @Nonnull Optional<INode> translateCommon(
            @Nonnull IValue<Tree> value,
            @Nonnull DetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {
        if (value instanceof KeySize<Tree> keySize) {
            KeyLength keyLength = new KeyLength(keySize.getValue(), detectionLocation);
            return Optional.of(keyLength);
        } else if (value instanceof MacSize<Tree> macSize) {
            TagLength tagLength = new TagLength(macSize.getValue(), detectionLocation);
            return Optional.of(tagLength);
        } else if (value instanceof TagSize<Tree> tagSize) {
            TagLength tagLength = new TagLength(tagSize.getValue(), detectionLocation);
            return Optional.of(tagLength);
        } else if (value instanceof InitializationVectorSize<Tree> initializationVectorSize) {
            InitializationVectorLength initializationVectorLength =
                    new InitializationVectorLength(
                            initializationVectorSize.getValue(), detectionLocation);
            return Optional.of(initializationVectorLength);
        } else if (value instanceof Mode<Tree> mode) {
            final JcaModeMapper modeMapper = new JcaModeMapper();
            return modeMapper.parse(mode.asString(), detectionLocation).map(a -> a);
        }
        return Optional.empty();
    }
}
