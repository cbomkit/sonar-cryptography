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
package com.ibm.plugin.rules.detection.gocrypto;

import com.ibm.engine.model.CipherAction;
import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.factory.CipherActionFactory;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.plugins.go.api.Tree;

/**
 * Detection rules for Go's crypto/rc4 package.
 *
 * <p>Detects usage of:
 *
 * <ul>
 *   <li>rc4.NewCipher(key) - creates a new RC4 stream cipher
 *   <li>(*Cipher).XORKeyStream(dst, src) - encrypts/decrypts using XOR with key stream
 * </ul>
 */
@SuppressWarnings("java:S1192")
public final class GoCryptoRC4 {

    private GoCryptoRC4() {
        // private
    }

    // (*rc4.Cipher).XORKeyStream(dst, src []byte)
    // Encrypts/decrypts using XOR with the key stream
    private static final IDetectionRule<Tree> XOR_KEY_STREAM =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("*rc4.Cipher", "rc4.Cipher")
                    .forMethods("XORKeyStream")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.ENCRYPT))
                    .withMethodParameter("[]byte") // dst
                    .withMethodParameter("[]byte") // src
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // rc4.NewCipher(key []byte) (*Cipher, error)
    // Creates a new RC4 stream cipher. Key must be 1-256 bytes.
    private static final IDetectionRule<Tree> NEW_CIPHER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/rc4")
                    .forMethods("NewCipher")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RC4"))
                    .withMethodParameter("[]byte") // key
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "GoCrypto")
                    .withDependingDetectionRules(List.of(XOR_KEY_STREAM));

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(NEW_CIPHER);
    }
}
