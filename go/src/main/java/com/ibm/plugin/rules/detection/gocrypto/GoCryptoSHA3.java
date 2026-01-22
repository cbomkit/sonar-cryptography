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

import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.plugins.go.api.Tree;

/**
 * Detection rules for Go's golang.org/x/crypto/sha3 package.
 *
 * <p>Detects usage of:
 *
 * <ul>
 *   <li>sha3.New224() - SHA3-224 hash
 *   <li>sha3.New256() - SHA3-256 hash
 *   <li>sha3.New384() - SHA3-384 hash
 *   <li>sha3.New512() - SHA3-512 hash
 *   <li>sha3.Sum224() - Direct SHA3-224 hash computation
 *   <li>sha3.Sum256() - Direct SHA3-256 hash computation
 *   <li>sha3.Sum384() - Direct SHA3-384 hash computation
 *   <li>sha3.Sum512() - Direct SHA3-512 hash computation
 *   <li>sha3.NewShake128() - SHAKE128 extendable output function
 *   <li>sha3.NewShake256() - SHAKE256 extendable output function
 * </ul>
 */
@SuppressWarnings("java:S1192")
public final class GoCryptoSHA3 {

    private GoCryptoSHA3() {
        // private
    }

    // sha3.New224() returns a new SHA3-224 hash
    private static final IDetectionRule<Tree> NEW_224 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("golang.org/x/crypto/sha3")
                    .forMethods("New224")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA3-224"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // sha3.New256() returns a new SHA3-256 hash
    private static final IDetectionRule<Tree> NEW_256 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("golang.org/x/crypto/sha3")
                    .forMethods("New256")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA3-256"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // sha3.New384() returns a new SHA3-384 hash
    private static final IDetectionRule<Tree> NEW_384 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("golang.org/x/crypto/sha3")
                    .forMethods("New384")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA3-384"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // sha3.New512() returns a new SHA3-512 hash
    private static final IDetectionRule<Tree> NEW_512 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("golang.org/x/crypto/sha3")
                    .forMethods("New512")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA3-512"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // sha3.Sum224(data []byte) [28]byte - computes SHA3-224 hash
    private static final IDetectionRule<Tree> SUM_224 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("golang.org/x/crypto/sha3")
                    .forMethods("Sum224")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA3-224"))
                    .withMethodParameter("*")
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // sha3.Sum256(data []byte) [32]byte - computes SHA3-256 hash
    private static final IDetectionRule<Tree> SUM_256 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("golang.org/x/crypto/sha3")
                    .forMethods("Sum256")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA3-256"))
                    .withMethodParameter("*")
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // sha3.Sum384(data []byte) [48]byte - computes SHA3-384 hash
    private static final IDetectionRule<Tree> SUM_384 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("golang.org/x/crypto/sha3")
                    .forMethods("Sum384")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA3-384"))
                    .withMethodParameter("*")
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // sha3.Sum512(data []byte) [64]byte - computes SHA3-512 hash
    private static final IDetectionRule<Tree> SUM_512 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("golang.org/x/crypto/sha3")
                    .forMethods("Sum512")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA3-512"))
                    .withMethodParameter("*")
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // sha3.NewShake128() returns a new SHAKE128 variable-output-length hash
    private static final IDetectionRule<Tree> NEW_SHAKE_128 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("golang.org/x/crypto/sha3")
                    .forMethods("NewShake128")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHAKE128"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // sha3.NewShake256() returns a new SHAKE256 variable-output-length hash
    private static final IDetectionRule<Tree> NEW_SHAKE_256 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("golang.org/x/crypto/sha3")
                    .forMethods("NewShake256")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHAKE256"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(
                NEW_224,
                NEW_256,
                NEW_384,
                NEW_512,
                SUM_224,
                SUM_256,
                SUM_384,
                SUM_512,
                NEW_SHAKE_128,
                NEW_SHAKE_256);
    }
}
