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
 * Detection rules for Go's crypto/sha256 package.
 *
 * <p>Detects usage of:
 *
 * <ul>
 *   <li>sha256.New() - creates a new SHA-256 hash
 *   <li>sha256.New224() - creates a new SHA-224 hash
 *   <li>sha256.Sum256(data) - computes SHA-256 checksum of data
 *   <li>sha256.Sum224(data) - computes SHA-224 checksum of data
 * </ul>
 */
@SuppressWarnings("java:S1192")
public final class GoCryptoSHA256 {

    private GoCryptoSHA256() {
        // private
    }

    // sha256.New() hash.Hash
    // Returns a new hash.Hash computing the SHA-256 checksum
    private static final IDetectionRule<Tree> NEW =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/sha256")
                    .forMethods("New")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA256"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // sha256.New224() hash.Hash
    // Returns a new hash.Hash computing the SHA-224 checksum
    private static final IDetectionRule<Tree> NEW224 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/sha256")
                    .forMethods("New224")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA224"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // sha256.Sum256(data []byte) [Size]byte
    // Returns the SHA-256 checksum of the data
    private static final IDetectionRule<Tree> SUM256 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/sha256")
                    .forMethods("Sum256")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA256"))
                    .withMethodParameter("[]byte")
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // sha256.Sum224(data []byte) [Size]byte
    // Returns the SHA-224 checksum of the data
    private static final IDetectionRule<Tree> SUM224 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/sha256")
                    .forMethods("Sum224")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA224"))
                    .withMethodParameter("[]byte")
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(NEW, NEW224, SUM256, SUM224);
    }
}
