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
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.IterationCountFactory;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;

/**
 * Detection rules for {@code PbeParameters} and {@code ExportPkcs12}.
 *
 * <p>{@code PbeParameters} states how an exported key or certificate is password-protected: the
 * cipher, the hash and the iteration count. It is passed to {@code ExportEncryptedPkcs8PrivateKey},
 * {@code ExportPkcs12}, {@code Pkcs12Builder} and {@code Pkcs8PrivateKeyInfo.Encrypt}.
 *
 * <p>The cipher argument is the root of the finding, because it decides the scheme: the AES values
 * are PBES2, {@code TripleDes3KeyPkcs12} is PKCS#12. The hash and the iteration count are its
 * children. If the cipher cannot be resolved, nothing is reported.
 *
 * <p>{@code ExportPkcs12} also accepts a {@code Pkcs12ExportPbeParameters} member that names cipher
 * and hash together; that one is detected at the export call.
 */
@SuppressWarnings("java:S1192")
public final class DotNetPbeParameters extends DetectionRuleSet<CSharpTree> {

    // new PbeParameters(encryptionAlgorithm, hashAlgorithm, iterationCount)
    private static final IDetectionRule<CSharpTree> PBE_PARAMETERS =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("PbeParameters")
                    .forMethods("<init>")
                    .withNamedMethodParameter("encryptionAlgorithm", "PbeEncryptionAlgorithm")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withNamedMethodParameter("hashAlgorithm", "HashAlgorithmName")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(0)
                    .withNamedMethodParameter("iterationCount", "int")
                    .shouldBeDetectedAs(new IterationCountFactory<>())
                    .asChildOfParameterWithId(0)
                    .buildForContext(new KeyContext(Map.of("kind", "PBE")))
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // cert.ExportPkcs12(Pkcs12ExportPbeParameters.X, password)
    private static final IDetectionRule<CSharpTree> PKCS12_EXPORT =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("ExportPkcs12")
                    .withNamedMethodParameter("exportParameters", "Pkcs12ExportPbeParameters")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withNamedMethodParameter("password", MethodMatcher.ANY)
                    .buildForContext(new KeyContext(Map.of("kind", "PBE")))
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    @Nonnull
    @Override
    protected List<IDetectionRule<CSharpTree>> buildRules() {
        return List.of(PBE_PARAMETERS, PKCS12_EXPORT);
    }
}
