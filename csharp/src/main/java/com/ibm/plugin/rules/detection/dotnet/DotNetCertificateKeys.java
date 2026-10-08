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
import com.ibm.engine.model.context.DetectionContext;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.engine.model.context.PublicKeyContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import javax.annotation.Nonnull;

/**
 * Detection rules for asymmetric keys obtained from an X.509 certificate.
 *
 * <p>Covers the certificate key accessors of {@code System.Security.Cryptography.X509Certificates}
 * — the extension methods on {@code X509Certificate2} declared by {@code RSACertificateExtensions},
 * {@code ECDsaCertificateExtensions}, {@code DSACertificateExtensions} and {@code
 * ECDiffieHellmanCertificateExtensions} (method names verified against the official API reference):
 *
 * <ul>
 *   <li>{@code GetRSAPrivateKey()} / {@code GetRSAPublicKey()} → RSA
 *   <li>{@code GetECDsaPrivateKey()} / {@code GetECDsaPublicKey()} → ECDSA
 *   <li>{@code GetDSAPrivateKey()} / {@code GetDSAPublicKey()} → DSA
 *   <li>{@code GetECDiffieHellmanPrivateKey()} / {@code GetECDiffieHellmanPublicKey()} → ECDH
 * </ul>
 *
 * <p>These close a real coverage hole rather than adding detail to an existing finding: code that
 * only ever takes its key material from a certificate never calls {@code RSA.Create()} or {@code
 * ECDsa.Create()}, so before these rules such a file produced <em>no asymmetric algorithm finding
 * at all</em>. That is not a corner case — certificate-backed signing and decryption is the
 * mainstream .NET pattern, and the two projects this plugin is exercised against contain six such
 * call sites (Bitwarden's license signing and verification, and ASP.NET Core Data Protection's
 * {@code EncryptedXmlDecryptor}), none of which were visible in the generated CBOM.
 *
 * <p>The receiver is matched as {@link MethodMatcher#ANY} because it is a certificate variable, not
 * a type name; the method names themselves are unique enough in this namespace to identify the
 * algorithm unambiguously. The operations performed on the returned key object are already covered
 * by the {@code Encrypt}/{@code Decrypt}/{@code SignData}/{@code VerifyData} depending rules of
 * {@link DotNetRSA}, {@link DotNetECDsa} and {@link DotNetDSA}, which is why these rules attach
 * those same depending-rule sets.
 */
public final class DotNetCertificateKeys extends DetectionRuleSet<CSharpTree> {

    /**
     * One rule per accessor, because the method name is what tells the two apart.
     *
     * <p>{@code GetRSAPrivateKey} and {@code GetRSAPublicKey} used to share a rule and a plain
     * {@link KeyContext}, which collapsed the one piece of information these accessors carry for
     * free. The context class picks the key node ({@code PrivateKeyContext} → {@link
     * com.ibm.mapper.model.PrivateKey}), while the {@code kind} property still names the algorithm,
     * so {@code CSharpKeyContextTranslator}'s existing {@code kind} switch is untouched.
     */
    @Nonnull
    private static IDetectionRule<CSharpTree> certificateKeyRule(
            @Nonnull DetectionContext context,
            @Nonnull String algorithmValue,
            @Nonnull List<IDetectionRule<CSharpTree>> dependingRules,
            @Nonnull String... methodNames) {
        return new DetectionRuleBuilder<CSharpTree>()
                .createDetectionRule()
                .forObjectTypes(MethodMatcher.ANY)
                .forMethods(methodNames)
                .shouldBeDetectedAs(new ValueActionFactory<>(algorithmValue))
                .withoutParameters()
                .buildForContext(context)
                .inBundle(() -> "DotNet")
                .withDependingDetectionRules(dependingRules);
    }

    /**
     * The same accessor called as a plain static method, with the certificate as its argument.
     *
     * <p>{@code RSACertificateExtensions.GetRSAPublicKey(cert)} and {@code cert.GetRSAPublicKey()}
     * are the same method — C# extension methods can be called either way, and real code does both.
     * The extension-method form takes no arguments and the static form takes one, so the two need
     * separate rules and cannot match the same call: the arity tells them apart, which is also why
     * adding this form cannot double-count the other. Eight call sites in the corpus this plugin is
     * exercised against use the static form, and all eight were invisible while the rules declared
     * {@code withoutParameters()} only.
     *
     * <p>The receiver is pinned to the declaring extension class rather than {@link
     * MethodMatcher#ANY}, because for a static call the receiver is a type name we know exactly,
     * and a one-argument method of the same name on an unrelated type should not match.
     */
    @Nonnull
    private static IDetectionRule<CSharpTree> staticCertificateKeyRule(
            @Nonnull DetectionContext context,
            @Nonnull String extensionClass,
            @Nonnull String algorithmValue,
            @Nonnull List<IDetectionRule<CSharpTree>> dependingRules,
            @Nonnull String methodName) {
        return new DetectionRuleBuilder<CSharpTree>()
                .createDetectionRule()
                .forObjectTypes(extensionClass)
                .forMethods(methodName)
                .shouldBeDetectedAs(new ValueActionFactory<>(algorithmValue))
                .withMethodParameter(MethodMatcher.ANY) // the certificate
                .buildForContext(context)
                .inBundle(() -> "DotNet")
                .withDependingDetectionRules(dependingRules);
    }

    @Nonnull
    private static List<IDetectionRule<CSharpTree>> keyPairRules(
            @Nonnull String algorithmValue,
            @Nonnull String extensionClass,
            @Nonnull List<IDetectionRule<CSharpTree>> dependingRules,
            @Nonnull String privateAccessor,
            @Nonnull String publicAccessor) {
        final Map<String, String> kind = Map.of("kind", algorithmValue);
        return List.of(
                certificateKeyRule(
                        new PrivateKeyContext(kind),
                        algorithmValue,
                        dependingRules,
                        privateAccessor),
                certificateKeyRule(
                        new PublicKeyContext(kind), algorithmValue, dependingRules, publicAccessor),
                staticCertificateKeyRule(
                        new PrivateKeyContext(kind),
                        extensionClass,
                        algorithmValue,
                        dependingRules,
                        privateAccessor),
                staticCertificateKeyRule(
                        new PublicKeyContext(kind),
                        extensionClass,
                        algorithmValue,
                        dependingRules,
                        publicAccessor));
    }

    @Nonnull
    @Override
    protected List<IDetectionRule<CSharpTree>> buildRules() {
        return Stream.of(
                        keyPairRules(
                                "RSA",
                                "RSACertificateExtensions",
                                DotNetRSA.dependingRules(),
                                "GetRSAPrivateKey",
                                "GetRSAPublicKey"),
                        keyPairRules(
                                "ECDSA",
                                "ECDsaCertificateExtensions",
                                List.of(),
                                "GetECDsaPrivateKey",
                                "GetECDsaPublicKey"),
                        keyPairRules(
                                "DSA",
                                "DSACertificateExtensions",
                                List.of(),
                                "GetDSAPrivateKey",
                                "GetDSAPublicKey"),
                        keyPairRules(
                                "ECDH",
                                "ECDiffieHellmanCertificateExtensions",
                                List.of(),
                                "GetECDiffieHellmanPrivateKey",
                                "GetECDiffieHellmanPublicKey"))
                .flatMap(List::stream)
                .toList();
    }
}
