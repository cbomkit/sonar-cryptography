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

import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.openssl.cipher.OpenSSLEvpCipher;
import com.ibm.plugin.rules.detection.openssl.digest.OpenSSLNameCanonicalizerFactory;
import com.ibm.plugin.rules.detection.openssl.legacy.OpenSSLNidLookupFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;

/**
 * Detection rules for OpenSSL keys created from raw bytes: MAC keys (HMAC, CMAC, Poly1305, SipHash)
 * and X25519, X448, Ed25519 and Ed448 private keys. The key type and the key length are reported,
 * and the operations performed with the key are followed as for a generated key (see {@link
 * OpenSSLEvpKeyUsage}), e.g. the HMAC computed with {@code EVP_DigestSign}.
 */
public final class OpenSSLEvpRawKey {

    private static final String BUNDLE = "OpenSSL";

    /** The context of a key created from raw bytes, a secret key or a private key by its type. */
    private static final Map<String, String> RAW_KEY = Map.of("kind", "RAW_KEY");

    private static final OpenSSLNidLookupFactory RAW_KEY_TYPE =
            new OpenSSLNidLookupFactory(
                    OpenSSLNidLookupFactory.RAW_KEY_TYPE_BY_CODE,
                    OpenSSLNidLookupFactory.RAW_KEY_TYPE_BY_NAME);

    // EVP_PKEY_new_mac_key(type, e, key, keylen) / EVP_PKEY_new_raw_private_key(type, e, priv, len)
    private static final IDetectionRule<AstNode> EVP_PKEY_NEW_RAW_KEY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_new_mac_key", "EVP_PKEY_new_raw_private_key")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(RAW_KEY_TYPE)
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(0)
                    .buildForContext(new KeyContext(RAW_KEY))
                    .inBundle(() -> BUNDLE)
                    .withDependingDetectionRules(OpenSSLEvpKeyUsage.rules());

    // EVP_PKEY_new_raw_private_key_ex(libctx, keytype, propq, priv, len)
    private static final IDetectionRule<AstNode> EVP_PKEY_NEW_RAW_PRIVATE_KEY_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_new_raw_private_key_ex")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLNameCanonicalizerFactory(
                                    OpenSSLNameCanonicalizerFactory.RAW_KEY_TYPE_NAMES, true))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(1)
                    .buildForContext(new KeyContext(RAW_KEY))
                    .inBundle(() -> BUNDLE)
                    .withDependingDetectionRules(OpenSSLEvpKeyUsage.rules());

    // EVP_PKEY_new_CMAC_key(e, priv, len, cipher)
    private static final IDetectionRule<AstNode> EVP_PKEY_NEW_CMAC_KEY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_new_CMAC_key")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMAC"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("*")
                    .addDependingDetectionRules(OpenSSLEvpCipher.cipherSelectionRules())
                    .buildForContext(new KeyContext(RAW_KEY))
                    .inBundle(() -> BUNDLE)
                    .withDependingDetectionRules(OpenSSLEvpKeyUsage.rules());

    private OpenSSLEvpRawKey() {
        // private
    }

    @Nonnull
    static List<IDetectionRule<AstNode>> rules() {
        return List.of(
                EVP_PKEY_NEW_RAW_KEY, EVP_PKEY_NEW_RAW_PRIVATE_KEY_EX, EVP_PKEY_NEW_CMAC_KEY);
    }
}
