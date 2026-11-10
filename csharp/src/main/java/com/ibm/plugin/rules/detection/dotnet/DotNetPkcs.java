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

import com.ibm.engine.detection.MethodMatcher;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.MacContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.IterationCountFactory;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rules for {@code System.Security.Cryptography.Pkcs}.
 *
 * <ul>
 *   <li>{@code Pkcs12Builder.SealWithMac(password, hashAlgorithm, iterationCount)}: the integrity
 *       HMAC of a PFX file, with its iteration count
 *   <li>{@code Rfc3161TimestampRequest.CreateFromData/CreateFromHash/CreateFromSignerInfo}: the
 *       digest of a timestamp request
 * </ul>
 *
 * <p>The hash is the root of each finding; an unresolved hash gives no finding.
 *
 * <p>Not covered: the password-based encryption of a PFX or PKCS#8 key, which {@link
 * DotNetPbeParameters} detects where the {@code PbeParameters} is created, and {@code
 * CmsRecipient}, whose overloads move the padding argument between positions.
 */
@SuppressWarnings("java:S1192")
public final class DotNetPkcs extends DetectionRuleSet<CSharpTree> {

    // builder.SealWithMac(password, hashAlgorithm, iterationCount)
    private static final IDetectionRule<CSharpTree> SEAL_WITH_MAC =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("SealWithMac")
                    .withNamedMethodParameter("password", MethodMatcher.ANY)
                    .withNamedMethodParameter("hashAlgorithm", "HashAlgorithmName")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withNamedMethodParameter("iterationCount", "int")
                    .shouldBeDetectedAs(new IterationCountFactory<>())
                    .asChildOfParameterWithId(1)
                    .buildForContext(new MacContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // One rule per timestamp factory; they differ only in the name of the first parameter.
    @Nonnull
    private static IDetectionRule<CSharpTree> timestampRequest(
            @Nonnull String method, @Nonnull String firstParameter) {
        return new DetectionRuleBuilder<CSharpTree>()
                .createDetectionRule()
                .forObjectTypes("Rfc3161TimestampRequest")
                .forMethods(method)
                .withNamedMethodParameter(firstParameter, MethodMatcher.ANY)
                .withNamedMethodParameter("hashAlgorithm", "HashAlgorithmName")
                .shouldBeDetectedAs(new AlgorithmFactory<>())
                .withOptionalNamedMethodParameter("requestedPolicyId", MethodMatcher.ANY)
                .withOptionalNamedMethodParameter("nonce", MethodMatcher.ANY)
                .withOptionalNamedMethodParameter("requestSignerCertificates", MethodMatcher.ANY)
                .withOptionalNamedMethodParameter("extensions", MethodMatcher.ANY)
                .buildForContext(new DigestContext())
                .inBundle(() -> "DotNet")
                .withoutDependingDetectionRules();
    }

    @Nonnull
    @Override
    protected List<IDetectionRule<CSharpTree>> buildRules() {
        return List.of(
                SEAL_WITH_MAC,
                timestampRequest("CreateFromData", "data"),
                timestampRequest("CreateFromHash", "hash"),
                timestampRequest("CreateFromSignerInfo", "signerInfo"));
    }
}
