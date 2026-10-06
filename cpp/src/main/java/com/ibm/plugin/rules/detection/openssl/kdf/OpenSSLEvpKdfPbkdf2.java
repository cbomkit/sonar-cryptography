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
import com.ibm.engine.model.factory.IterationCountFactory;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.model.factory.SaltSizeFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.ibm.plugin.rules.detection.openssl.OpenSSLSizeFactory;
import com.ibm.plugin.rules.detection.openssl.digest.OpenSSLEvpMessageDigest;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.function.Supplier;
import javax.annotation.Nonnull;

/**
 * Detection rules for the OpenSSL PKCS#5 PBKDF2 functions {@code PKCS5_PBKDF2_HMAC} and {@code
 * PKCS5_PBKDF2_HMAC_SHA1}. The salt length, the iteration count and the length of the derived key
 * are reported with the KDF, and the digest of {@code PKCS5_PBKDF2_HMAC} is traced back to where it
 * is selected.
 */
@SuppressWarnings("java:S1192")
public final class OpenSSLEvpKdfPbkdf2 {

    private static final String BUNDLE = "OpenSSL";

    private OpenSSLEvpKdfPbkdf2() {
        // private
    }

    // PKCS5_PBKDF2_HMAC(pass, passlen, salt, saltlen, iter, digest, keylen, out)
    private static final IDetectionRule<AstNode> PKCS5_PBKDF2_HMAC =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("PKCS5_PBKDF2_HMAC")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PBKDF2-HMAC"))
                    .withMethodParameter("*") // pass
                    .withMethodParameter("*") // passlen
                    .withMethodParameter("*") // salt
                    .withMethodParameter("*") // saltlen
                    .shouldBeDetectedAs(
                            new OpenSSLSizeFactory(new SaltSizeFactory<>(Size.UnitType.BYTE)))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("*") // iter
                    .shouldBeDetectedAs(new IterationCountFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("*") // digest
                    .addDependingDetectionRules(OpenSSLEvpMessageDigest.rules())
                    .withMethodParameter("*") // keylen
                    .shouldBeDetectedAs(
                            new OpenSSLSizeFactory(new KeySizeFactory<>(Size.UnitType.BYTE)))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("*") // out
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // PKCS5_PBKDF2_HMAC_SHA1(pass, passlen, salt, saltlen, iter, keylen, out)
    private static final IDetectionRule<AstNode> PKCS5_PBKDF2_HMAC_SHA1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("PKCS5_PBKDF2_HMAC_SHA1")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PBKDF2-HMAC-SHA1"))
                    .withMethodParameter("*") // pass
                    .withMethodParameter("*") // passlen
                    .withMethodParameter("*") // salt
                    .withMethodParameter("*") // saltlen
                    .shouldBeDetectedAs(
                            new OpenSSLSizeFactory(new SaltSizeFactory<>(Size.UnitType.BYTE)))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("*") // iter
                    .shouldBeDetectedAs(new IterationCountFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("*") // keylen
                    .shouldBeDetectedAs(
                            new OpenSSLSizeFactory(new KeySizeFactory<>(Size.UnitType.BYTE)))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("*") // out
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final Supplier<List<IDetectionRule<AstNode>>> RULES =
            Memoize.of(OpenSSLEvpKdfPbkdf2::buildRules);

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return RULES.get();
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> buildRules() {
        return List.of(PKCS5_PBKDF2_HMAC, PKCS5_PBKDF2_HMAC_SHA1);
    }
}
