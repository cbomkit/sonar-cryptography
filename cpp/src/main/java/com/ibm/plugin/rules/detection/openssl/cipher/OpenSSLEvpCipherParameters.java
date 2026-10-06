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
package com.ibm.plugin.rules.detection.openssl.cipher;

import com.ibm.engine.language.cxx.CxxLanguageTranslation;
import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.AlgorithmParameterContext;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.ibm.plugin.rules.detection.openssl.OpenSSLSizeFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.function.Supplier;
import javax.annotation.Nonnull;

/**
 * Detection rules for the parameters set on an OpenSSL cipher context: the key length ({@code
 * EVP_CIPHER_CTX_set_key_length}), the padding ({@code EVP_CIPHER_CTX_set_padding}) and the key
 * length, IV length and tag length set with {@code EVP_CIPHER_CTX_ctrl}. These are depending rules
 * of the creation of the context ({@link OpenSSLEvpCipherContext}), as the JCA parameter
 * specifications are given to {@code Cipher.init}.
 */
public final class OpenSSLEvpCipherParameters {

    private static final String BUNDLE = "OpenSSL";

    // EVP_CIPHER_CTX_set_key_length(ctx, keylen): the key length in bytes
    private static final IDetectionRule<AstNode> EVP_CIPHER_CTX_SET_KEY_LENGTH =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_CIPHER_CTX_set_key_length")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLSizeFactory(new KeySizeFactory<>(Size.UnitType.BYTE)))
                    .buildForContext(new AlgorithmParameterContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // EVP_CIPHER_CTX_set_padding(ctx, pad): the standard block padding unless pad is 0
    private static final IDetectionRule<AstNode> EVP_CIPHER_CTX_SET_PADDING =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_CIPHER_CTX_set_padding")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new OpenSSLCipherPaddingFactory())
                    .buildForContext(new AlgorithmParameterContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // EVP_CIPHER_CTX_ctrl(ctx, type, arg, ptr): the parameter the command type sets, given by arg
    private static final IDetectionRule<AstNode> EVP_CIPHER_CTX_CTRL =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_CIPHER_CTX_ctrl")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new OpenSSLCipherCtrlFactory())
                    .withMethodParameter("*")
                    .buildForContext(new AlgorithmParameterContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private OpenSSLEvpCipherParameters() {
        // private
    }

    private static final Supplier<List<IDetectionRule<AstNode>>> RULES =
            Memoize.of(OpenSSLEvpCipherParameters::buildRules);

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return RULES.get();
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> buildRules() {
        return List.of(
                EVP_CIPHER_CTX_SET_KEY_LENGTH, EVP_CIPHER_CTX_SET_PADDING, EVP_CIPHER_CTX_CTRL);
    }
}
