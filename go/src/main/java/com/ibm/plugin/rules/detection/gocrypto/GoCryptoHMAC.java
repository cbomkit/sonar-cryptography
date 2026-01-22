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

import com.ibm.engine.model.context.MacContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import org.sonar.plugins.go.api.Tree;

import javax.annotation.Nonnull;
import java.util.List;
import java.util.Map;

/**
 * Detection rules for Go's crypto/hmac package.
 *
 * <p>Detects usage of:
 *
 * <ul>
 *   <li>hmac.New(h func() hash.Hash, key []byte) - creates a new HMAC hash using the given hash
 *       function and key
 * </ul>
 *
 * <p>The first parameter is a hash constructor function (e.g., sha256.New, sha1.New, md5.New) which
 * is detected through depending detection rules.
 */
@SuppressWarnings("java:S1192")
public final class GoCryptoHMAC {

    private GoCryptoHMAC() {
        // private
    }

    // hmac.New(h func() hash.Hash, key []byte) hash.Hash
    // Returns a new HMAC hash using the given hash function and key
    private static final IDetectionRule<Tree> NEW =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/hmac")
                    .forMethods("New")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HMAC"))
                    .withMethodParameter("func() hash.Hash")
                    .addDependingDetectionRules(GoCryptoHash.rules())
                    .withMethodParameter("[]byte")
                    .buildForContext(new MacContext(Map.of("kind", "HMAC")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(NEW);
    }
}
