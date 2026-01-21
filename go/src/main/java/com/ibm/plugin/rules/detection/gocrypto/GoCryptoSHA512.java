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
 * Detection rules for Go's crypto/sha512 package.
 *
 * <p>Detects usage of:
 *
 * <ul>
 *   <li>sha512.New() - creates a new SHA-512 hash
 *   <li>sha512.New384() - creates a new SHA-384 hash
 *   <li>sha512.Sum512(data) - computes SHA-512 checksum of data
 *   <li>sha512.Sum384(data) - computes SHA-384 checksum of data
 * </ul>
 */
@SuppressWarnings("java:S1192")
public final class GoCryptoSHA512 {

    private GoCryptoSHA512() {
        // private
    }

    // sha512.New() hash.Hash
    // Returns a new hash.Hash computing the SHA-512 checksum
    private static final IDetectionRule<Tree> NEW =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/sha512")
                    .forMethods("New")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA512"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // sha512.New384() hash.Hash
    // Returns a new hash.Hash computing the SHA-384 checksum
    private static final IDetectionRule<Tree> NEW384 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/sha512")
                    .forMethods("New384")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA384"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // sha512.Sum512(data []byte) [Size]byte
    // Returns the SHA-512 checksum of the data
    private static final IDetectionRule<Tree> SUM512 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/sha512")
                    .forMethods("Sum512")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA512"))
                    .withMethodParameter("[]byte")
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // sha512.Sum384(data []byte) [Size]byte
    // Returns the SHA-384 checksum of the data
    private static final IDetectionRule<Tree> SUM384 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/sha512")
                    .forMethods("Sum384")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA384"))
                    .withMethodParameter("[]byte")
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(NEW, NEW384, SUM512, SUM384);
    }
}
