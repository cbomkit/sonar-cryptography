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
import com.ibm.engine.model.SignatureAction;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.PaddingFactory;
import com.ibm.engine.model.factory.SignatureActionFactory;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rules for {@code System.Security.Cryptography.Cose}.
 *
 * <p>A {@code CoseSigner} states its hash and, for RSA, its padding as constructor arguments, so it
 * is reported as a {@code Sign} with those as children, like {@link DotNetCertificateRequest}.
 * {@code SignEmbedded} and {@code SignDetached} add nothing and are not matched.
 *
 * <p>The RSA overload is {@code (key, signaturePadding, hashAlgorithm)}, the other {@code (key,
 * hashAlgorithm)}. One rule covers both, because two rules would overlap; the arguments are placed
 * by type.
 */
@SuppressWarnings("java:S1192")
public final class DotNetCose extends DetectionRuleSet<CSharpTree> {

    // new CoseSigner(key, signaturePadding, hashAlgorithm [, protectedHeaders [,
    // unprotectedHeaders]])
    // new CoseSigner(key, hashAlgorithm [, protectedHeaders [, unprotectedHeaders]])
    private static final IDetectionRule<CSharpTree> COSE_SIGNER =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("CoseSigner")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withNamedMethodParameter("key", MethodMatcher.ANY)
                    .withNamedMethodParameter("hashAlgorithm", "HashAlgorithmName")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withOptionalNamedMethodParameter("signaturePadding", "RSASignaturePadding")
                    .shouldBeDetectedAs(new PaddingFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withOptionalNamedMethodParameter("protectedHeaders", MethodMatcher.ANY)
                    .withOptionalNamedMethodParameter("unprotectedHeaders", MethodMatcher.ANY)
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    @Nonnull
    @Override
    protected List<IDetectionRule<CSharpTree>> buildRules() {
        return List.of(COSE_SIGNER);
    }
}
