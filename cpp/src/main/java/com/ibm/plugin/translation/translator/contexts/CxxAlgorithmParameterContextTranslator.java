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
import com.ibm.engine.model.InitializationVectorSize;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.Padding;
import com.ibm.engine.model.TagSize;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.InitializationVectorLength;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.TagLength;
import com.ibm.mapper.model.padding.PKCS7;
import com.ibm.mapper.utils.DetectionLocation;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.Optional;
import javax.annotation.Nonnull;

public final class CxxAlgorithmParameterContextTranslator implements IContextTranslation<AstNode> {

    @Override
    public @Nonnull Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<AstNode> value,
            @Nonnull IDetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {
        // parameters set on a cipher context (see OpenSSLEvpCipherParameters)
        if (value instanceof KeySize<AstNode> keySize) {
            return Optional.of(new KeyLength(keySize.getValue(), detectionLocation));
        } else if (value instanceof TagSize<AstNode> tagSize) {
            return Optional.of(new TagLength(tagSize.getValue(), detectionLocation));
        } else if (value instanceof InitializationVectorSize<AstNode> initializationVectorSize) {
            return Optional.of(
                    new InitializationVectorLength(
                            initializationVectorSize.getValue(), detectionLocation));
        } else if (value instanceof Padding<AstNode> padding
                && "PKCS7".equals(padding.asString())) {
            // the standard block padding (EVP_CIPHER_CTX_set_padding)
            return Optional.of(new PKCS7(detectionLocation));
        }
        return Optional.empty();
    }
}
