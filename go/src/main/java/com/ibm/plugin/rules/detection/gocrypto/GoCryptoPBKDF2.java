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

import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.factory.IterationCountFactory;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.model.factory.SaltSizeFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import org.sonar.plugins.go.api.Tree;

/**
 * Detection rules for Go's PBKDF2 implementations.
 *
 * <p>Detects usage of:
 *
 * <ul>
 *   <li>golang.org/x/crypto/pbkdf2.Key(password, salt, iter, keyLen, h) - legacy API
 *   <li>crypto/pbkdf2.Key(h, password, salt, iter, keyLength) - stdlib API (Go 1.24+)
 * </ul>
 */
@SuppressWarnings("java:S1192")
public final class GoCryptoPBKDF2 {

    private GoCryptoPBKDF2() {
        // private
    }

    // golang.org/x/crypto/pbkdf2.Key(password, salt []byte, iter, keyLen int, h func() hash.Hash)
    // Legacy API - derives a key from a password using PBKDF2
    private static final IDetectionRule<Tree> KEY_LEGACY =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("golang.org/x/crypto/pbkdf2")
                    .forMethods("Key")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PBKDF2"))
                    .withMethodParameter("[]byte") // password
                    .withMethodParameter("[]byte") // salt
                    .shouldBeDetectedAs(new SaltSizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("int") // iter
                    .shouldBeDetectedAs(new IterationCountFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("int") // keyLen
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("func() hash.Hash") // h
                    .addDependingDetectionRules(GoCryptoHash.rules())
                    .buildForContext(new KeyContext(Map.of("kind", "KDF")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // crypto/pbkdf2.Key[Hash hash.Hash](h func() Hash, password string, salt []byte, iter,
    // keyLength int)
    // Stdlib API (Go 1.24+) - derives a key from a password using PBKDF2
    private static final IDetectionRule<Tree> KEY_STDLIB =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/pbkdf2")
                    .forMethods("Key")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PBKDF2"))
                    .withMethodParameter("func() hash.Hash") // h
                    .addDependingDetectionRules(GoCryptoHash.rules())
                    .withMethodParameter("string") // password
                    .withMethodParameter("[]byte") // salt
                    .shouldBeDetectedAs(new SaltSizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("int") // iter
                    .shouldBeDetectedAs(new IterationCountFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("int") // keyLength
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new KeyContext(Map.of("kind", "KDF")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(KEY_LEGACY, KEY_STDLIB);
    }
}
