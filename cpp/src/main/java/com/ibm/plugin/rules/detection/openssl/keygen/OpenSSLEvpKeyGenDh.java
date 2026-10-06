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
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.factory.IValueFactory;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.ibm.plugin.rules.detection.openssl.OpenSSLSizeFactory;
import com.ibm.plugin.rules.detection.openssl.legacy.OpenSSLNidLookupFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;
import javax.annotation.Nonnull;

/**
 * Detection rules for the Diffie-Hellman settings of an OpenSSL key generation context: the size of
 * the prime, given directly or through a named group. They apply to the calls made on a context
 * created by one of the rules of {@link OpenSSLEvpKeyGen}.
 */
public final class OpenSSLEvpKeyGenDh {

    private static final String BUNDLE = "OpenSSL";

    /** RFC 5114 group number (1, 2 or 3) → size of its prime. */
    private static final Map<Integer, Integer> RFC5114_PRIME_BITS =
            Map.of(1, 1024, 2, 2048, 3, 2048);

    private static final IValueFactory<AstNode> RFC5114_GROUP_SIZE =
            resolvedValue ->
                    resolvedValue.value() instanceof Number group
                                    && RFC5114_PRIME_BITS.containsKey(group.intValue())
                            ? Optional.of(
                                    new KeySize<>(
                                            RFC5114_PRIME_BITS.get(group.intValue()),
                                            Size.UnitType.BIT,
                                            resolvedValue.tree()))
                            : Optional.empty();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_DH_PARAMGEN_PRIME_LEN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_PKEY_CTX_set_dh_paramgen_prime_len")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLSizeFactory(new KeySizeFactory<>(Size.UnitType.BIT)))
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_DH_NID =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_PKEY_CTX_set_dh_nid")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLNidLookupFactory(
                                    OpenSSLNidLookupFactory.DH_GROUP_BY_CODE,
                                    OpenSSLNidLookupFactory.DH_GROUP_BY_NAME,
                                    code -> code,
                                    // "DH-2048" → the size of the group's prime
                                    (label, tree) ->
                                            new KeySize<>(
                                                    Integer.parseInt(label.substring(3)),
                                                    Size.UnitType.BIT,
                                                    tree)))
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_DH_RFC5114 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_PKEY_CTX_set_dh_rfc5114", "EVP_PKEY_CTX_set_dhx_rfc5114")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(RFC5114_GROUP_SIZE)
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private OpenSSLEvpKeyGenDh() {
        // private
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> buildRules() {
        return List.of(
                EVP_PKEY_CTX_SET_DH_PARAMGEN_PRIME_LEN,
                EVP_PKEY_CTX_SET_DH_NID,
                EVP_PKEY_CTX_SET_DH_RFC5114);
    }

    private static final Supplier<List<IDetectionRule<AstNode>>> RULES =
            Memoize.of(OpenSSLEvpKeyGenDh::buildRules);

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return RULES.get();
    }
}
