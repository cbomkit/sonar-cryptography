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
package com.ibm.plugin.rules.detection.openssl.keygen;

import com.ibm.engine.language.cxx.CxxLanguageTranslation;
import com.ibm.engine.model.Curve;
import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.engine.model.factory.KeyActionFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.ibm.plugin.rules.detection.openssl.digest.OpenSSLNameCanonicalizerFactory;
import com.ibm.plugin.rules.detection.openssl.legacy.OpenSSLNidLookupFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Stream;
import javax.annotation.Nonnull;

/**
 * Detection rules for OpenSSL EVP key and parameter generation.
 *
 * <p>The key type is selected when the key generation context is created, by {@code
 * EVP_PKEY_CTX_new_id} or {@code EVP_PKEY_CTX_new_from_name}, and the calls made on that context
 * configure and run the generation:
 *
 * <pre>{@code
 * EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
 * EVP_PKEY_keygen_init(ctx);
 * EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 3072);
 * EVP_PKEY_keygen(ctx, &pkey);
 * }</pre>
 *
 * <p>{@code EVP_PKEY_Q_keygen} does all of this in one call. A generated key is reported as a
 * private key holding its algorithm. Domain parameters generated on such a context ({@code
 * EVP_PKEY_paramgen}) are reported as the algorithm with the settings made on the context. The
 * operations performed with a generated key are reported on it (see {@link OpenSSLEvpKeyUsage}).
 * The settings specific to RSA, DSA and Diffie-Hellman are in their own {@code
 * OpenSSLEvpKeyGen<Family>} classes.
 */
public final class OpenSSLEvpKeyGen {

    private static final String BUNDLE = "OpenSSL";

    // Calls made on a key generation context

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_GROUP_NAME =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_PKEY_CTX_set_group_name")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new OpenSSLKeyParameterFactory())
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_EC_PARAMGEN_CURVE_NID =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_PKEY_CTX_set_ec_paramgen_curve_nid")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLNidLookupFactory(
                                    OpenSSLNidLookupFactory.CURVE_BY_CODE,
                                    OpenSSLNidLookupFactory.CURVE_BY_NAME,
                                    code -> code,
                                    Curve::new))
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // EVP_PKEY_keygen(ctx, &pkey) / EVP_PKEY_generate(ctx, &pkey): the key is returned in pkey,
    // whose uses are followed
    private static final IDetectionRule<AstNode> EVP_PKEY_KEYGEN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_PKEY_keygen", "EVP_PKEY_generate")
                    .shouldBeDetectedAs(
                            new KeyActionFactory<>(KeyAction.Action.PRIVATE_KEY_GENERATION))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withDependingDetectionRules(OpenSSLEvpKeyUsage.rules());

    private static final List<IDetectionRule<AstNode>> KEY_GENERATION_CONTEXT_RULES =
            Stream.of(
                            OpenSSLEvpKeyGenRsa.rules().stream(),
                            OpenSSLEvpKeyGenDsa.rules().stream(),
                            OpenSSLEvpKeyGenDh.rules().stream(),
                            Stream.of(
                                    EVP_PKEY_CTX_SET_GROUP_NAME,
                                    EVP_PKEY_CTX_SET_EC_PARAMGEN_CURVE_NID,
                                    EVP_PKEY_KEYGEN))
                    .flatMap(i -> i)
                    .toList();

    // Key type selection

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_NEW_ID =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_PKEY_CTX_new_id")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLNidLookupFactory(
                                    OpenSSLNidLookupFactory.PKEY_TYPE_BY_CODE,
                                    OpenSSLNidLookupFactory.PKEY_TYPE_BY_NAME))
                    .withMethodParameter("*")
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withDependingDetectionRules(KEY_GENERATION_CONTEXT_RULES);

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_NEW_FROM_NAME =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_PKEY_CTX_new_from_name")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLNameCanonicalizerFactory(
                                    OpenSSLNameCanonicalizerFactory.KEY_TYPE_NAMES, true))
                    .withMethodParameter("*")
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withDependingDetectionRules(KEY_GENERATION_CONTEXT_RULES);

    // EVP_PKEY_Q_keygen(libctx, propq, type, ...): the size of an RSA key or the curve of an EC
    // key follows the type

    private static final IDetectionRule<AstNode> EVP_PKEY_Q_KEYGEN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_PKEY_Q_keygen")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLNameCanonicalizerFactory(
                                    OpenSSLNameCanonicalizerFactory.KEY_TYPE_NAMES, true))
                    .buildForContext(new PrivateKeyContext(Map.of()))
                    .inBundle(() -> BUNDLE)
                    .withDependingDetectionRules(OpenSSLEvpKeyUsage.rules());

    private static final IDetectionRule<AstNode> EVP_PKEY_Q_KEYGEN_WITH_PARAMETER =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_PKEY_Q_keygen")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLNameCanonicalizerFactory(
                                    OpenSSLNameCanonicalizerFactory.KEY_TYPE_NAMES, true))
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new OpenSSLKeyParameterFactory())
                    .asChildOfParameterWithId(2)
                    .buildForContext(new PrivateKeyContext(Map.of()))
                    .inBundle(() -> BUNDLE)
                    .withDependingDetectionRules(OpenSSLEvpKeyUsage.rules());

    // EVP_RSA_gen(bits) and EVP_EC_gen(curve) (rsa.h, ec.h): EVP_PKEY_Q_keygen for an RSA key of
    // the given size and an EC key on the given curve

    private static final IDetectionRule<AstNode> EVP_RSA_GEN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_RSA_gen")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA"))
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new OpenSSLKeyParameterFactory())
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new PrivateKeyContext(Map.of()))
                    .inBundle(() -> BUNDLE)
                    .withDependingDetectionRules(OpenSSLEvpKeyUsage.rules());

    private static final IDetectionRule<AstNode> EVP_EC_GEN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_EC_gen")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EC"))
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new OpenSSLKeyParameterFactory())
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new PrivateKeyContext(Map.of()))
                    .inBundle(() -> BUNDLE)
                    .withDependingDetectionRules(OpenSSLEvpKeyUsage.rules());

    private static final IDetectionRule<AstNode> EVP_KEYMGMT_FETCH =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_KEYMGMT_fetch")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLNameCanonicalizerFactory(
                                    OpenSSLNameCanonicalizerFactory.KEY_TYPE_NAMES, true))
                    .withMethodParameter("*")
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private OpenSSLEvpKeyGen() {
        // private
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> buildRules() {
        return Stream.of(
                        Stream.of(
                                EVP_PKEY_CTX_NEW_ID,
                                EVP_PKEY_CTX_NEW_FROM_NAME,
                                EVP_PKEY_Q_KEYGEN,
                                EVP_PKEY_Q_KEYGEN_WITH_PARAMETER,
                                EVP_RSA_GEN,
                                EVP_EC_GEN,
                                EVP_KEYMGMT_FETCH),
                        // keys created from raw bytes
                        OpenSSLEvpRawKey.rules().stream())
                .flatMap(i -> i)
                .toList();
    }

    private static final Supplier<List<IDetectionRule<AstNode>>> RULES =
            Memoize.of(OpenSSLEvpKeyGen::buildRules);

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return RULES.get();
    }
}
