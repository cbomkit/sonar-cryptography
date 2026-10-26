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
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rules for {@code System.Security.Cryptography.Xml}.
 *
 * <p>XML Signature and XML Encryption name algorithms by W3C URI, written as a literal or as a
 * {@code SignedXml} or {@code EncryptedXml} constant:
 *
 * <ul>
 *   <li>{@code reference.DigestMethod = …}: a digest
 *   <li>{@code signedInfo.SignatureMethod = …}: a signature algorithm or an HMAC. The chained form
 *       {@code signedXml.SignedInfo.SignatureMethod = …} is detected too.
 *   <li>{@code new EncryptionMethod(algorithm)} and {@code method.KeyAlgorithm = …}: a cipher or a
 *       key-transport algorithm
 * </ul>
 *
 * <p>The URIs are read by {@code DotNetXmlAlgorithmUris}. An unknown URI gives no node.
 */
@SuppressWarnings("java:S1192")
public final class DotNetXml extends DetectionRuleSet<CSharpTree> {

    // reference.DigestMethod = SignedXml.XmlDsigSHA256Url
    private static final IDetectionRule<CSharpTree> REFERENCE_DIGEST_METHOD =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("set_DigestMethod")
                    .withMethodParameter(MethodMatcher.ANY)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // signedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA256Url
    private static final IDetectionRule<CSharpTree> SIGNATURE_METHOD =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("set_SignatureMethod")
                    .withMethodParameter(MethodMatcher.ANY)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // new EncryptionMethod(EncryptedXml.XmlEncAES256Url)
    private static final IDetectionRule<CSharpTree> ENCRYPTION_METHOD =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("EncryptionMethod")
                    .forMethods("<init>")
                    .withNamedMethodParameter("algorithm", "string")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // encryptionMethod.KeyAlgorithm = EncryptedXml.XmlEncAES256Url
    private static final IDetectionRule<CSharpTree> ENCRYPTION_KEY_ALGORITHM =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("set_KeyAlgorithm")
                    .withMethodParameter(MethodMatcher.ANY)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    @Nonnull
    @Override
    protected List<IDetectionRule<CSharpTree>> buildRules() {
        return List.of(
                REFERENCE_DIGEST_METHOD,
                SIGNATURE_METHOD,
                ENCRYPTION_METHOD,
                ENCRYPTION_KEY_ALGORITHM);
    }
}
