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
package com.ibm.plugin.rules.detection.openssl.kdf;

import com.ibm.engine.language.cxx.CxxLanguageTranslation;
import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.KeyDerivationFunctionContext;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.model.factory.SaltSizeFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.openssl.OpenSSLSizeFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rules for the OpenSSL scrypt function {@code EVP_PBE_scrypt} and its {@code
 * EVP_PBE_scrypt_ex} variant (evp.h). The salt length and the length of the derived key are
 * reported with the KDF. Scrypt selected by name through {@code EVP_KDF_fetch} or by key type
 * through {@code EVP_PKEY_CTX_new_id} is covered by {@link OpenSSLEvpKdf}.
 */
@SuppressWarnings("java:S1192")
public final class OpenSSLEvpKdfScrypt extends DetectionRuleSet<AstNode> {

    private static final String BUNDLE = "OpenSSL";

    // EVP_PBE_scrypt(pass, passlen, salt, saltlen, N, r, p, maxmem, key, keylen)
    private static final IDetectionRule<AstNode> EVP_PBE_SCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_PBE_scrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SCRYPT"))
                    .withMethodParameter("*") // pass
                    .withMethodParameter("*") // passlen
                    .withMethodParameter("*") // salt
                    .withMethodParameter("*") // saltlen
                    .shouldBeDetectedAs(
                            new OpenSSLSizeFactory(new SaltSizeFactory<>(Size.UnitType.BYTE)))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("*") // N
                    .withMethodParameter("*") // r
                    .withMethodParameter("*") // p
                    .withMethodParameter("*") // maxmem
                    .withMethodParameter("*") // key
                    .withMethodParameter("*") // keylen
                    .shouldBeDetectedAs(
                            new OpenSSLSizeFactory(new KeySizeFactory<>(Size.UnitType.BYTE)))
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // EVP_PBE_scrypt_ex(pass, passlen, salt, saltlen, N, r, p, maxmem, key, keylen, ctx, propq)
    private static final IDetectionRule<AstNode> EVP_PBE_SCRYPT_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_PBE_scrypt_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SCRYPT"))
                    .withMethodParameter("*") // pass
                    .withMethodParameter("*") // passlen
                    .withMethodParameter("*") // salt
                    .withMethodParameter("*") // saltlen
                    .shouldBeDetectedAs(
                            new OpenSSLSizeFactory(new SaltSizeFactory<>(Size.UnitType.BYTE)))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("*") // N
                    .withMethodParameter("*") // r
                    .withMethodParameter("*") // p
                    .withMethodParameter("*") // maxmem
                    .withMethodParameter("*") // key
                    .withMethodParameter("*") // keylen
                    .shouldBeDetectedAs(
                            new OpenSSLSizeFactory(new KeySizeFactory<>(Size.UnitType.BYTE)))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("*") // ctx
                    .withMethodParameter("*") // propq
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    @Nonnull
    @Override
    protected List<IDetectionRule<AstNode>> buildRules() {
        return List.of(EVP_PBE_SCRYPT, EVP_PBE_SCRYPT_EX);
    }
}
