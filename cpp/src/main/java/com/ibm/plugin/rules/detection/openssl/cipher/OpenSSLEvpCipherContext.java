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
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.RuleSets;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.stream.Stream;
import javax.annotation.Nonnull;

/**
 * Detection rule for the creation of an OpenSSL cipher context, {@code EVP_CIPHER_CTX_new()}. The
 * context is followed to the calls made on it: its initialization with a cipher ({@link
 * OpenSSLEvpCipherInit}) and the parameters set on it ({@link OpenSSLEvpCipherParameters}), which
 * are reported together, as the JCA {@code Cipher.getInstance} rules report the {@code Cipher.init}
 * made on the cipher:
 *
 * <pre>{@code
 * EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
 * EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
 * EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
 * EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
 * }</pre>
 */
public final class OpenSSLEvpCipherContext extends DetectionRuleSet<AstNode> {

    private static final String BUNDLE = "OpenSSL";

    private static final IDetectionRule<AstNode> EVP_CIPHER_CTX_NEW =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_CIPHER_CTX_new")
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withDependingDetectionRules(
                            Stream.concat(
                                            RuleSets.rulesOf(OpenSSLEvpCipherInit.class).stream(),
                                            RuleSets.rulesOf(OpenSSLEvpCipherParameters.class)
                                                    .stream())
                                    .toList());

    @Nonnull
    @Override
    protected List<IDetectionRule<AstNode>> buildRules() {
        return List.of(EVP_CIPHER_CTX_NEW);
    }
}
