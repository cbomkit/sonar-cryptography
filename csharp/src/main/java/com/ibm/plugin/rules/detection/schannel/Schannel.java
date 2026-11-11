/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2026 PQCA
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
package com.ibm.plugin.rules.detection.schannel;

import com.ibm.engine.detection.MethodMatcher;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.engine.model.context.ProtocolContext;
import com.ibm.engine.model.factory.ProtocolFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;

/**
 * Schannel driven directly through SSPI from C#, i.e. hand-written P/Invoke against {@code
 * secur32.dll} rather than {@code SslStream}.
 *
 * <h2>What "Schannel in C#" means, and which reading these rules cover</h2>
 *
 * <p>Three different things go by that name, and only one of them is unclaimed:
 *
 * <ul>
 *   <li>{@code SslStream} and {@code SslClientAuthenticationOptions} <em>are</em> Schannel on
 *       Windows, but every place they state a version is already read by {@code DotNetTls} --
 *       {@code AuthenticateAsClient}/{@code Server}, {@code set_EnabledSslProtocols}, {@code
 *       set_SslProtocols}, {@code set_SecurityProtocol}, {@code UseHttps}. A second rule on any of
 *       those methods would match the same call and report it twice, so none is touched here.
 *   <li>{@code CipherSuitesPolicy} is declared {@code [UnsupportedOSPlatform("windows")]}: it
 *       configures the OpenSSL-backed stack and throws on the Schannel-backed one. Whatever it is,
 *       it is not Schannel, so it has no place in this rule set.
 *   <li>Direct SSPI/Schannel P/Invoke -- {@code AcquireCredentialsHandle} with {@code
 *       SCHANNEL_CRED} or {@code SCH_CREDENTIALS}. That is what these rules read.
 * </ul>
 *
 * <h2>What the Schannel API actually lets a caller state</h2>
 *
 * <p>Much less than its field list suggests, and this is the governing fact for the whole rule set.
 * Of everything reachable from a credential structure, exactly one field is an allow-list:
 *
 * <ul>
 *   <li>{@code SCHANNEL_CRED.grbitEnabledProtocols} -- "a bit string that represents the protocols
 *       <em>supported</em> by connections made with credentials acquired by using this structure".
 *       Read here.
 *   <li>{@code TLS_PARAMETERS.grbitDisabledProtocols} -- the same flag vocabulary with the opposite
 *       meaning. Not read; see below.
 *   <li>{@code TLS_PARAMETERS.pDisabledCrypto}, an array of {@code CRYPTO_SETTINGS}. The
 *       structure's own documentation page is titled "Indicates <em>disabled</em> cryptographic
 *       settings" and its usage enum is documented as "Specifies the algorithm being used <em>to
 *       disable</em> cryptographic settings". Not read; see below.
 * </ul>
 *
 * <p>The modern {@code SCH_CREDENTIALS} structure has no {@code grbitEnabledProtocols}, no {@code
 * dwMinimumCipherStrength} and no {@code palgSupportedAlgs} at all: it carries nothing positive
 * about cryptography, only the deny-lists above. So on the newer API there is no algorithm, key
 * size, cipher suite or chaining mode that a caller can <em>request</em> -- only ones it can
 * forbid.
 *
 * <h2>Why the deny-lists produce nothing</h2>
 *
 * <p>{@code grbitDisabledProtocols} has no rule, and neither have {@code eAlgorithmUsage}, {@code
 * strCngAlgId}, {@code rgstrChainingModes}, {@code dwMinBitLength} and {@code dwMaxBitLength}. A
 * disabled protocol is not a protocol in use and a disabled algorithm is not an algorithm in use;
 * CycloneDX has no component for "deliberately not used", and emitting the ordinary one would state
 * the exact opposite of what the source says. The inverse reading -- "AES was disabled below 256
 * bits, therefore AES-256 is in force" -- needs the platform's full default suite list and
 * certainty that nothing else narrows it, which is a guess rather than a reading.
 *
 * <p>The canonical implementation makes the point concrete. {@code SslStreamPal.Windows.cs} writes
 * {@code tlsParameters.grbitDisabledProtocols = (uint)protocolFlags ^ uint.MaxValue;} -- a computed
 * complement, with no flag name in it to read even if one wanted to -- and fills {@code
 * pDisabledCrypto} with {@code TlsParametersCngAlgUsageCertSig} entries naming {@code
 * "SCH_RSA_PKCS_PAD"} and {@code "SCH_RSA_PSS_PAD"}, whose whole purpose is to switch RSA
 * certificate-signature padding <em>off</em>. A rule reading those as "RSA PKCS#1 is used here"
 * would invert the meaning of the code it is looking at.
 *
 * <h2>Why these three rules, and what each guards on</h2>
 *
 * <p>{@code dwMinimumCipherStrength} and {@code dwMaximumCipherStrength} are genuinely positive --
 * a floor and a ceiling on bulk cipher key length -- but they name no algorithm, and a bit length
 * with nothing to attach it to is not a component. They are left unread rather than hung off an
 * invented algorithm or off a bare {@code TLS}, where a policy floor would read as an observed key
 * length. {@code palgSupportedAlgs} is positive too and names {@code ALG_ID} values, but it is a
 * pointer to a pinned array: the assignment holds an address expression, never the algorithm names,
 * so there is nothing at that call site to read.
 *
 * <p>{@code InitializeSecurityContext}, {@code AcceptSecurityContext}, {@code EncryptMessage},
 * {@code DecryptMessage}, {@code ApplyControlToken} and {@code QueryContextAttributes} take a
 * handle and carry no package name. Nothing at those call sites distinguishes a TLS context from a
 * Kerberos or NTLM one, so none of them is matched -- an SSPI {@code EncryptMessage} is not
 * evidence of TLS.
 */
@SuppressWarnings("java:S1192")
public final class Schannel extends DetectionRuleSet<CSharpTree> {

    /** The closed set of Schannel package names; see {@code CSharpProtocolContextTranslator}. */
    private static final String KIND_PACKAGE = "SCHANNEL_PACKAGE";

    /** The closed set of {@code SP_PROT_*} flag names. */
    private static final String KIND_PROTOCOLS = "SCHANNEL_PROTOCOLS";

    private static final String TLS = "TLS";

    /**
     * {@code AcquireCredentialsHandle(null, UNISP_NAME, SECPKG_CRED_OUTBOUND, ...)} -- the one call
     * in the SSPI sequence that names the security package.
     *
     * <p>SSPI is not TLS. The same nine-parameter function acquires Kerberos, NTLM, Negotiate and
     * CredSSP credentials, and {@code pszPackage} at index 1 is the only thing that says which. So
     * the rule has no method-level detection: the package name is the sole value read, and the
     * translator reports TLS only for a member of the closed set {@code {UNISP_NAME,
     * SCHANNEL_NAME}} and their {@code _A}/{@code _W} spellings and literal string values. {@code
     * "Negotiate"} resolves cleanly and yields nothing, which is the point.
     *
     * <p>All nine parameters are declared although only one is read, because the binder accepts a
     * call only at an arity within {@code [required, declared]} and this function is always called
     * with nine arguments. The Win32 names are used, but they are not what makes the binding work:
     * hand-written P/Invoke names these parameters whatever the author likes -- .NET's own
     * declaration calls them {@code principal, moduleName, usage, ...} -- so index 1 is what
     * carries it. Declaring {@code pszPackage} as {@code string} is what stops the package name
     * being taken from somewhere else: the three other reference parameters at lower indices are
     * pointers and buffers.
     *
     * <p>No version is read. A credential's protocols live in the structure passed as {@code
     * pAuthData}, which is a pointer expression here and is read instead at the field assignments
     * below. A bare {@code TLS} is the honest statement for the call itself, and it is the same one
     * {@code DotNetTls} makes for {@code UseHttps} and for {@code SslProtocols.None}.
     */
    private static final IDetectionRule<CSharpTree> ACQUIRE_CREDENTIALS_HANDLE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods(
                            "AcquireCredentialsHandle",
                            "AcquireCredentialsHandleA",
                            "AcquireCredentialsHandleW")
                    .withNamedMethodParameter("pszPrincipal", MethodMatcher.ANY)
                    .withNamedMethodParameter("pszPackage", "string")
                    .shouldBeDetectedAs(new ProtocolFactory<>())
                    .withNamedMethodParameter("fCredentialUse", MethodMatcher.ANY)
                    .withNamedMethodParameter("pvLogonId", MethodMatcher.ANY)
                    .withNamedMethodParameter("pAuthData", MethodMatcher.ANY)
                    .withNamedMethodParameter("pGetKeyFn", MethodMatcher.ANY)
                    .withNamedMethodParameter("pvGetKeyArgument", MethodMatcher.ANY)
                    .withNamedMethodParameter("phCredential", MethodMatcher.ANY)
                    .withNamedMethodParameter("ptsExpiry", MethodMatcher.ANY)
                    .buildForContext(new ProtocolContext(Map.of("kind", KIND_PACKAGE)))
                    .inBundle(() -> "Schannel")
                    .withoutDependingDetectionRules();

    /**
     * {@code new SCHANNEL_CRED { ... }} and {@code new SCH_CREDENTIALS { ... }}.
     *
     * <p>These two structures exist for one purpose. Unlike the fields read below, the type name
     * here really is the receiver text a rule can match on -- a creation carries its own type --
     * and a type spelled {@code SCHANNEL_CRED} cannot plausibly be anything but the Schannel
     * credential, whatever namespace a consumer declares it in. Both spellings are the ones Windows
     * uses, which is what every published P/Invoke declaration copies, including .NET's own.
     *
     * <p>The creation is worth a rule of its own because the documentation recommends leaving the
     * protocols alone: "applications should set {@code grbitEnabledProtocols} to zero and use the
     * protocol versions enabled on the system by default". A credential built that way states that
     * Schannel TLS is configured here and says nothing about versions, and this is what records it.
     *
     * <p>A credential written {@code SCH_CREDENTIALS cred = default;}, which is how .NET itself
     * writes it, is not a creation and is not matched. Such code reaches {@code
     * AcquireCredentialsHandle} to be of any use, and that rule covers it.
     */
    private static final IDetectionRule<CSharpTree> CREDENTIAL_STRUCTURE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("SCHANNEL_CRED", "SCH_CREDENTIALS")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>(TLS))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(Map.of("kind", KIND_PACKAGE)))
                    .inBundle(() -> "Schannel")
                    .withoutDependingDetectionRules();

    /**
     * {@code cred.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT;} -- the
     * only allow-list in the Schannel API, and the one place a version is stated.
     *
     * <p>The receiver is {@code ANY} and it has to be. A field assignment and an object-initializer
     * entry both arrive as a synthetic {@code set_<Name>} call on the <em>variable</em> the
     * structure is held in, not on its type, and the C# frontend has no semantic model to recover a
     * variable's declared type. So the field name is the entire guard -- and it is a good one:
     * {@code grbitEnabledProtocols} is a Win32 Hungarian-notation name that belongs to exactly one
     * structure in the world. This is also why the rules below key on the field name rather than on
     * the structure's C# name, which a consumer is free to spell as they like.
     *
     * <p>A flags combination resolves to each of its members rather than to a number, so {@code A |
     * B} states two protocols; the same machinery that makes {@code SslProtocols.Tls12 |
     * SslProtocols.Tls13} report both versions handles it unchanged. {@code SP_PROT_NONE} (zero)
     * means Schannel chooses, which is reported as TLS without a version -- exactly what is known.
     *
     * <p><b>Known limitation, and why it is not closed here.</b> A flag arrives as a name only when
     * it is written as a member access ({@code Schannel.SP_PROT_TLS1_2_CLIENT}), which is how
     * .NET's own code and every multi-file P/Invoke writes it. A bare reference to a {@code const
     * int} declared in the same file resolves through that constant to its value instead, and a
     * value is not a name, so such an assignment reports nothing rather than guessing. That is a
     * recall gap, not a precision one.
     *
     * <p>Decoding the number would be sound in principle -- the field is a bit string over a
     * closed, documented set of values -- but it is not done, and one of the two reasons for that
     * has since changed. It used to be that the spelling decided whether a number arrived at all:
     * {@code CSharpTreeConverter} recognized only {@code INTEGER_LITERAL}, so {@code 2048} resolved
     * to an {@code Integer} while {@code 0x800} fell through to the string fallback and reached the
     * translator as the raw source text {@code "0x00000800"}. Both spellings now classify as {@code
     * INTEGER}, so the asymmetry is gone; the outcome is unchanged, because a protocol factory
     * refuses an {@code Integer} either way, and the {@code NumericFlag} counter-check in {@code
     * SchannelTest} pins that.
     *
     * <p>What still rules it out is the second reason: a translator maps one value to one node, so
     * a field carrying several bits could not be represented even where the bits are unambiguous.
     * Decoding would also have to reproduce the header's aliasing -- {@code 0x80} is both {@code
     * SP_PROT_TLS1_CLIENT} and {@code SP_PROT_TLS1_0_CLIENT} -- which the names above express
     * directly. A uniform gap is better than a partial decode.
     */
    private static final IDetectionRule<CSharpTree> ENABLED_PROTOCOLS =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("set_grbitEnabledProtocols")
                    .withMethodParameter(MethodMatcher.ANY)
                    .shouldBeDetectedAs(new ProtocolFactory<>())
                    .buildForContext(new ProtocolContext(Map.of("kind", KIND_PROTOCOLS)))
                    .inBundle(() -> "Schannel")
                    .withoutDependingDetectionRules();

    @Nonnull
    @Override
    protected List<IDetectionRule<CSharpTree>> buildRules() {
        return List.of(ACQUIRE_CREDENTIALS_HANDLE, CREDENTIAL_STRUCTURE, ENABLED_PROTOCOLS);
    }
}
