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
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.DetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.InitializationVectorLength;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.TagLength;
import com.ibm.mapper.model.algorithms.MGF1;
import com.ibm.mapper.model.padding.OAEP;
import com.ibm.mapper.model.padding.PKCS7;
import com.ibm.mapper.utils.DetectionLocation;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.Optional;
import javax.annotation.Nonnull;

public final class CxxAlgorithmParameterContextTranslator implements IContextTranslation<AstNode> {

    /** The setting of the digest of RSA-OAEP. */
    public static final String OAEP_SETTING = "OAEP";

    /** The setting of the digest of the MGF1 mask generation function. */
    public static final String MGF1_SETTING = "MGF1";

    @Override
    public @Nonnull Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<AstNode> value,
            @Nonnull DetectionContext detectionContext,
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
        } else if (value instanceof ValueAction<AstNode> setting) {
            // the setting of an RSA padding whose digest is given as the argument of the setter,
            // e.g. EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) and EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md)
            return switch (setting.asString()) {
                case OAEP_SETTING -> Optional.of(new OAEP(detectionLocation));
                case MGF1_SETTING -> Optional.of(new MGF1(detectionLocation));
                default -> Optional.empty();
            };
        }
        return Optional.empty();
    }
}
