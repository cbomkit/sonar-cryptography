/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2024 PQCA
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
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
package com.ibm.plugin.rules.detection.libsodium;

import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rules for the libsodium AEAD encryption APIs.
 */
public final class LibsodiumAead {

    private static final String BUNDLE = "Libsodium";

    private static final IDetectionRule<AstNode> CHACHA20_POLY1305 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods(
                            "crypto_aead_chacha20poly1305_ietf_encrypt",
                            "crypto_aead_chacha20poly1305_ietf_decrypt",
                            "crypto_aead_xchacha20poly1305_ietf_encrypt",
                            "crypto_aead_xchacha20poly1305_ietf_decrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ChaCha20-Poly1305"))
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> XSALSA20_POLY1305 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("crypto_secretbox_easy", "crypto_secretbox_open_easy")
                    .shouldBeDetectedAs(new ValueActionFactory<>("XSalsa20-Poly1305"))
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private LibsodiumAead() {
        // private
    }

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(CHACHA20_POLY1305, XSALSA20_POLY1305);
    }
}
