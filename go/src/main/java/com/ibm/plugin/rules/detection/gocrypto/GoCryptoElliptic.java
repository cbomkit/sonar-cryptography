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

import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import org.sonar.plugins.go.api.Tree;

/**
 * Detection rules for Go's crypto/elliptic package.
 *
 * <p>Detects usage of:
 *
 * <ul>
 *   <li>elliptic.P224() - returns a Curve implementing NIST P-224
 *   <li>elliptic.P256() - returns a Curve implementing NIST P-256
 *   <li>elliptic.P384() - returns a Curve implementing NIST P-384
 *   <li>elliptic.P521() - returns a Curve implementing NIST P-521
 * </ul>
 */
public final class GoCryptoElliptic {

    private GoCryptoElliptic() {
        // private
    }

    // elliptic.P224() elliptic.Curve
    // Returns a Curve which implements NIST P-224
    private static final IDetectionRule<Tree> P224 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/elliptic")
                    .forMethods("P224")
                    .shouldBeDetectedAs(new ValueActionFactory<>("P-224"))
                    .withoutParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "EC")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // elliptic.P256() elliptic.Curve
    // Returns a Curve which implements NIST P-256
    private static final IDetectionRule<Tree> P256 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/elliptic")
                    .forMethods("P256")
                    .shouldBeDetectedAs(new ValueActionFactory<>("P-256"))
                    .withoutParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "EC")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // elliptic.P384() elliptic.Curve
    // Returns a Curve which implements NIST P-384
    private static final IDetectionRule<Tree> P384 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/elliptic")
                    .forMethods("P384")
                    .shouldBeDetectedAs(new ValueActionFactory<>("P-384"))
                    .withoutParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "EC")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // elliptic.P521() elliptic.Curve
    // Returns a Curve which implements NIST P-521
    private static final IDetectionRule<Tree> P521 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/elliptic")
                    .forMethods("P521")
                    .shouldBeDetectedAs(new ValueActionFactory<>("P-521"))
                    .withoutParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "EC")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(P224, P256, P384, P521);
    }
}
