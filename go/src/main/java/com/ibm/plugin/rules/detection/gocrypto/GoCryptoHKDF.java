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
 * Detection rules for Go's golang.org/x/crypto/hkdf package.
 *
 * <p>Detects usage of:
 *
 * <ul>
 *   <li>hkdf.New(hash, secret, salt, info) - creates an HKDF reader
 *   <li>hkdf.Extract(hash, secret, salt) - HKDF extract step
 *   <li>hkdf.Expand(hash, prk, info, keyLen) - HKDF expand step
 * </ul>
 */
@SuppressWarnings("java:S1192")
public final class GoCryptoHKDF {

    private GoCryptoHKDF() {
        // private
    }

    // hkdf.New(hash func() hash.Hash, secret, salt, info []byte) io.Reader
    // Returns an HKDF reader that combines Extract and Expand
    private static final IDetectionRule<Tree> NEW =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("golang.org/x/crypto/hkdf")
                    .forMethods("New")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HKDF"))
                    .withMethodParameter("func() hash.Hash")
                    .addDependingDetectionRules(GoCryptoHash.rules())
                    .withMethodParameter("[]byte")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("[]byte")
                    .shouldBeDetectedAs(new SaltSizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("[]byte")
                    .buildForContext(new KeyContext(Map.of("kind", "KDF")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // hkdf.Extract(hash func() hash.Hash, secret, salt []byte) []byte
    // HKDF extract step - extracts a pseudorandom key
    static final IDetectionRule<Tree> EXTRACT =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("golang.org/x/crypto/hkdf", "crypto/hkdf")
                    .forMethods("Extract")
                    .withMethodParameter("func() hash.Hash")
                    .addDependingDetectionRules(GoCryptoHash.rules())
                    .withMethodParameter("[]byte")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("[]byte")
                    .shouldBeDetectedAs(new SaltSizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new KeyContext(Map.of("kind", "KDF")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // hkdf.Expand(hash func() hash.Hash, pseudorandomKey, info []byte, keyLength int) io.Reader
    // HKDF expand step - expands a pseudorandom key to the desired length
    private static final IDetectionRule<Tree> EXPAND =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("golang.org/x/crypto/hkdf", "crypto/hkdf")
                    .forMethods("Expand")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HKDF"))
                    .withMethodParameter("func() hash.Hash")
                    .addDependingDetectionRules(GoCryptoHash.rules())
                    .withMethodParameter("[]byte")
                    .addDependingDetectionRules(List.of(EXTRACT))
                    .withMethodParameter("[]byte")
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new KeyContext(Map.of("kind", "KDF")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(NEW, EXPAND);
    }
}
