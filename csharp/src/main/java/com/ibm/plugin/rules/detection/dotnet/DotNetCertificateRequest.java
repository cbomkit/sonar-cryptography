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
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.PaddingFactory;
import com.ibm.engine.model.factory.SignatureActionFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;

/**
 * Detection rules for how a certificate is signed ({@code X509Certificates}).
 *
 * <ul>
 *   <li>{@code new CertificateRequest(subjectName, key, hashAlgorithm[, padding])}
 *   <li>{@code X509SignatureGenerator.CreateForRSA(key, signaturePadding)}
 *   <li>{@code X509SignatureGenerator.CreateForECDsa(key)}
 * </ul>
 *
 * <p>A request is reported as a {@code Sign} with the hash and, for RSA, the padding as children,
 * like {@code SignData}. {@code Create} and {@code CreateSelfSigned} add no information and are not
 * matched. One rule covers all constructor overloads; the {@code PublicKey} overload names its
 * second parameter {@code publicKey}, so only a keyword call to it is missed.
 *
 * <p>The key is not linked to the finding that created it. An unresolved hash or padding is left
 * off.
 */
@SuppressWarnings("java:S1192")
public final class DotNetCertificateRequest extends DetectionRuleSet<CSharpTree> {

    // new CertificateRequest(subjectName, key, hashAlgorithm [, padding])
    private static final IDetectionRule<CSharpTree> CERTIFICATE_REQUEST =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("CertificateRequest")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withNamedMethodParameter("subjectName", MethodMatcher.ANY)
                    .withNamedMethodParameter("key", MethodMatcher.ANY)
                    .withNamedMethodParameter("hashAlgorithm", "HashAlgorithmName")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withOptionalNamedMethodParameter("padding", "RSASignaturePadding")
                    .shouldBeDetectedAs(new PaddingFactory<>())
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // X509SignatureGenerator.CreateForRSA(key, signaturePadding)
    private static final IDetectionRule<CSharpTree> CREATE_FOR_RSA =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("X509SignatureGenerator")
                    .forMethods("CreateForRSA")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withNamedMethodParameter("key", MethodMatcher.ANY)
                    .withNamedMethodParameter("signaturePadding", "RSASignaturePadding")
                    .shouldBeDetectedAs(new PaddingFactory<>())
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // X509SignatureGenerator.CreateForECDsa(key)
    private static final IDetectionRule<CSharpTree> CREATE_FOR_ECDSA =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("X509SignatureGenerator")
                    .forMethods("CreateForECDsa")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDSA"))
                    .withNamedMethodParameter("key", MethodMatcher.ANY)
                    .buildForContext(new KeyContext(Map.of("kind", "ECDSA")))
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    @Nonnull
    @Override
    protected List<IDetectionRule<CSharpTree>> buildRules() {
        return List.of(CERTIFICATE_REQUEST, CREATE_FOR_RSA, CREATE_FOR_ECDSA);
    }
}
