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

import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.KeyDerivationFunctionContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.ibm.plugin.rules.detection.openssl.digest.OpenSSLNameCanonicalizerFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Stream;
import javax.annotation.Nonnull;

/**
 * Detection rules for OpenSSL Key Derivation Functions (KDFs).
 *
 * <p>These rules detect KDF usage through the EVP_KDF API introduced in OpenSSL 3.0. Covers PBKDF2,
 * HKDF, Scrypt, TLS PRF, X963KDF, KBKDF, Argon2, and other KDFs.
 *
 * <p>Argon2, HKDF, the TLS PRFs, and the PKCS#12/PKCS#5 family live in their own {@code
 * OpenSSLEvpKdf<Family>} classes; this class holds the remaining single-variant KDFs (PBKDF2,
 * Scrypt, X963KDF, KBKDF, SSHKDF, KRB5KDF, X942KDF, SSKDF, HMAC-DRBG-KDF, PVKKDF) and the generic
 * EVP_KDF CTX/derive infrastructure, and aggregates every family's rules in {@link #rules()}.
 */
@SuppressWarnings("java:S1192")
public final class OpenSSLEvpKdf {

    private static final String BUNDLE = "OpenSSL";

    private static final IDetectionRule<AstNode> PBKDF2_FETCH =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PBKDF2"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"PBKDF2\"")
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SCRYPT"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"SCRYPT\"")
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> X963KDF_FETCH =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("X963KDF"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"X963KDF\"")
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> KBKDF_FETCH =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("KBKDF"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"KBKDF\"")
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SSHKDF_FETCH =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SSHKDF"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"SSHKDF\"")
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> KRB5KDF =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("KRB5KDF"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"KRB5KDF\"")
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> X942KDF_ASN1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("X942KDF-ASN1"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"X942KDF-ASN1\"")
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> X942KDF_CONCAT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("X942KDF-CONCAT"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"X942KDF-CONCAT\"")
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SSKDF =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SSKDF"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"SSKDF\"")
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> HMAC_DRBG_KDF =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HMAC-DRBG-KDF"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"HMAC-DRBG-KDF\"")
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PVKKDF =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PVKKDF"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"PVKKDF\"")
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_KDF_CTX_NEW =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_CTX_new")
                    .shouldBeDetectedAs(new ValueActionFactory<>("KDF-CTX"))
                    .withAnyParameters()
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_KDF_CTX_SET_PARAMS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_CTX_set_params")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLParamsScannerFactory(
                                    "digest", OpenSSLNameCanonicalizerFactory.DIGEST_NAMES))
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private OpenSSLEvpKdf() {
        // private
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> buildRules() {
        return Stream.of(
                        OpenSSLEvpKdfArgon2.rules().stream(),
                        OpenSSLEvpKdfHkdf.rules().stream(),
                        OpenSSLEvpKdfTls.rules().stream(),
                        OpenSSLEvpKdfPkcs12.rules().stream(),
                        directRules().stream())
                .flatMap(i -> i)
                .toList();
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> directRules() {
        return List.of(
                // PBKDF2 - Password-Based Key Derivation Function 2
                PBKDF2_FETCH,
                // Scrypt
                SCRYPT,
                // X963KDF - ANSI X9.63 Key Derivation Function
                X963KDF_FETCH,
                // KBKDF - Key-Based Key Derivation Function (NIST SP 800-108)
                KBKDF_FETCH,
                // SSHKDF - SSH Key Derivation Function
                SSHKDF_FETCH,
                // KRB5KDF - Kerberos 5 Key Derivation Function
                KRB5KDF,
                // X942KDF - X9.42 Key Derivation Function
                X942KDF_ASN1,
                X942KDF_CONCAT,
                // SSKDF - Single Step Key Derivation Function (NIST SP 800-56C)
                SSKDF,
                // HMAC-DRBG-KDF - HMAC-based DRBG as KDF (NIST SP 800-90A)
                HMAC_DRBG_KDF,
                // PVKKDF - Microsoft PVK Key Derivation Function (Legacy)
                PVKKDF,
                // EVP_KDF CTX/derive
                EVP_KDF_CTX_NEW,
                EVP_KDF_CTX_SET_PARAMS);
    }

    private static final Supplier<List<IDetectionRule<AstNode>>> RULES =
            Memoize.of(OpenSSLEvpKdf::buildRules);

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return RULES.get();
    }
}
