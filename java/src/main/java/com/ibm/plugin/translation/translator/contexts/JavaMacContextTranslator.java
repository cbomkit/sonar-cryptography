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
import com.ibm.engine.model.MacSize;
import com.ibm.engine.model.ParameterIdentifier;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.DetectionContext;
import com.ibm.mapper.mapper.bc.BcMacMapper;
import com.ibm.mapper.mapper.jca.JcaMacMapper;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.ParameterSetIdentifier;
import com.ibm.mapper.model.TagLength;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

public final class JavaMacContextTranslator extends JavaAbstractLibraryTranslator {

    @Override
    protected @Nonnull Optional<INode> translateJCA(
            @Nonnull IValue<Tree> value,
            @Nonnull DetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {
        if (value instanceof com.ibm.engine.model.Algorithm<Tree>) {
            JcaMacMapper jcaMacMapper = new JcaMacMapper();
            return jcaMacMapper.parse(value.asString(), detectionLocation).map(a -> a);
        } else if (value instanceof MacSize<Tree> macSize) {
            TagLength tagLength = new TagLength(macSize.getValue(), detectionLocation);
            return Optional.of(tagLength);
        } else if (value instanceof BlockSize<Tree> blockSizeDetection) {
            com.ibm.mapper.model.BlockSize blockSize =
                    new com.ibm.mapper.model.BlockSize(
                            blockSizeDetection.getValue(), detectionLocation);
            return Optional.of(blockSize);
        }
        return Optional.empty();
    }

    @Override
    protected @Nonnull Optional<INode> translateBC(
            @Nonnull IValue<Tree> value,
            @Nonnull DetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {
        if (value instanceof ValueAction<Tree> valueAction) {
            BcMacMapper bcMacMapper = new BcMacMapper();
            return bcMacMapper.parse(valueAction.asString(), detectionLocation).map(f -> f);
        } else if (value instanceof MacSize<Tree> macSize) {
            TagLength tagLength = new TagLength(macSize.getValue(), detectionLocation);
            return Optional.of(tagLength);
        } else if (value instanceof BlockSize<Tree> blockSizeDetection) {
            com.ibm.mapper.model.BlockSize blockSize =
                    new com.ibm.mapper.model.BlockSize(
                            blockSizeDetection.getValue(), detectionLocation);
            return Optional.of(blockSize);
        } else if (value instanceof ParameterIdentifier<Tree> parameterIdentifier) {
            ParameterSetIdentifier parameterSetIdentifier =
                    new ParameterSetIdentifier(parameterIdentifier.asString(), detectionLocation);
            return Optional.of(parameterSetIdentifier);
        }
        return Optional.empty();
    }
}
