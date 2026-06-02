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
package com.ibm.plugin.rules.detection.dotnet;

import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rules for SHA hash algorithms in System.Security.Cryptography.
 *
 * <p>Detects factory methods and concrete class constructors for SHA-1, SHA-256, SHA-384, and
 * SHA-512 (and their {@code Managed} concrete variants).
 */
@SuppressWarnings("java:S1192")
public final class DotNetSHA {

    private DotNetSHA() {
        // nothing
    }

    // SHA1
    private static final IDetectionRule<CSharpTree> SHA1_CREATE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("SHA1")
                    .forMethods("Create")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA1"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    private static final IDetectionRule<CSharpTree> SHA1_MANAGED =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("SHA1Managed")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA1"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    // SHA256
    private static final IDetectionRule<CSharpTree> SHA256_CREATE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("SHA256")
                    .forMethods("Create")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA256"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    private static final IDetectionRule<CSharpTree> SHA256_MANAGED =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("SHA256Managed")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA256"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    // SHA384
    private static final IDetectionRule<CSharpTree> SHA384_CREATE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("SHA384")
                    .forMethods("Create")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA384"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    private static final IDetectionRule<CSharpTree> SHA384_MANAGED =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("SHA384Managed")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA384"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    // SHA512
    private static final IDetectionRule<CSharpTree> SHA512_CREATE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("SHA512")
                    .forMethods("Create")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA512"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    private static final IDetectionRule<CSharpTree> SHA512_MANAGED =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("SHA512Managed")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA512"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    // MD5
    private static final IDetectionRule<CSharpTree> MD5_CREATE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("MD5")
                    .forMethods("Create")
                    .shouldBeDetectedAs(new ValueActionFactory<>("MD5"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    private static final IDetectionRule<CSharpTree> MD5_CSP =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("MD5CryptoServiceProvider")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("MD5"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(List.of());

    @Nonnull
    public static List<IDetectionRule<CSharpTree>> rules() {
        return List.of(
                SHA1_CREATE,
                SHA1_MANAGED,
                SHA256_CREATE,
                SHA256_MANAGED,
                SHA384_CREATE,
                SHA384_MANAGED,
                SHA512_CREATE,
                SHA512_MANAGED,
                MD5_CREATE,
                MD5_CSP);
    }
}
