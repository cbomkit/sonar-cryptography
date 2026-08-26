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
import com.ibm.engine.model.CipherAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.factory.CipherActionFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rules for the Windows Data Protection API (DPAPI) surface of {@code
 * System.Security.Cryptography}.
 *
 * <p>Classes covered (per the official API reference, verified via WebFetch of learn.microsoft.com
 * — not guessed):
 *
 * <ul>
 *   <li>{@code ProtectedData} — static-only class ({@code System.Security.Cryptography} namespace,
 *       assembly {@code System.Security.Cryptography.ProtectedData.dll} / {@code
 *       System.Security.dll}). Methods: {@code Protect(byte[], byte[], DataProtectionScope)},
 *       {@code Protect(ReadOnlySpan<byte>, DataProtectionScope, ReadOnlySpan<byte>)}, {@code
 *       Protect(ReadOnlySpan<byte>, DataProtectionScope, Span<byte>, ReadOnlySpan<byte>)}, {@code
 *       TryProtect(...)}, and the {@code Unprotect}/{@code TryUnprotect} mirror overloads.
 *   <li>{@code ProtectedMemory} — static-only class (assembly {@code System.Security.dll}).
 *       Methods: {@code Protect(byte[], MemoryProtectionScope)}, {@code Unprotect(byte[],
 *       MemoryProtectionScope)}. No {@code Try*} variants are published for this class.
 *   <li>{@code DpapiDataProtector} — a real, documented class ({@code System.Security.Cryptography}
 *       namespace, assembly {@code System.Security.dll}), sealed and deriving from the abstract
 *       {@code DataProtector} base class. Verified via WebFetch to exist as an actual API member
 *       (not a misnaming of something from {@code Microsoft.AspNetCore.DataProtection}, which is an
 *       entirely different, unrelated API — the ASP.NET Core Data Protection stack has its own
 *       {@code IDataProtector}/{@code IDataProtectionProvider} types, not this class). Constructor
 *       {@code DpapiDataProtector(string appName, string primaryPurpose, params string[]
 *       specificPurpose)}; instance methods {@code Protect(byte[])}/{@code Unprotect(byte[])}
 *       (inherited, non-overridable, from {@code DataProtector}) delegate internally to {@code
 *       ProtectedData.Protect}/{@code Unprotect}. <b>Important availability caveat found during
 *       verification:</b> unlike {@code ProtectedData}/{@code ProtectedMemory} (which ship for
 *       modern .NET on Windows via the {@code System.Security.Cryptography.ProtectedData} NuGet
 *       package, per the moniker list on their doc pages: {@code netcore-1.0} onward, {@code
 *       windowsdesktop-*}, {@code net-11.0-pp}), {@code DpapiDataProtector}'s doc page lists
 *       <em>only</em> {@code netframework-4.5} through {@code netframework-4.8.1} monikers — it is
 *       .NET Framework legacy-only and has no modern-.NET equivalent. It remains valid, detectable
 *       legacy source, so it is covered here.
 * </ul>
 *
 * <p><b>Platform note:</b> per the official remarks on both {@code ProtectedData} and {@code
 * ProtectedMemory}, "this class provides access to the Data Protection API (DPAPI) available in
 * Windows operating systems" and its use "on platforms other than Windows throws a {@code
 * PlatformNotSupportedException}". This does not affect detection: these are source-level patterns
 * matched independently of the runtime platform the scanned code would actually execute on.
 *
 * <p><b>Modeling decision — algorithm identity:</b> DPAPI deliberately does not expose which
 * concrete symmetric algorithm it uses underneath (this has changed across Windows versions and is
 * not selectable by the caller), so translating it as a specific algorithm such as {@code AES} or
 * {@code DESede} would be inventing information that is not present in the source code. Instead,
 * following the same precedent as {@code CSharpPRNGContextTranslator}'s {@code "NATIVEPRNG"} (used
 * for .NET's {@code RandomNumberGenerator}, an equally vendor/platform-opaque primitive — see
 * {@link DotNetRandomNumberGenerator}), this file captures the vendor-specific value {@code
 * "DPAPI"} and dispatches it in {@code CSharpCipherContextTranslator} to the generic mapper {@code
 * Algorithm} constructor ({@code new Algorithm("DPAPI", Cipher.class, detectionLocation)}), using
 * the existing generic {@code Cipher} primitive marker interface (already present in the mapper
 * model, parent of {@code BlockCipher}/{@code StreamCipher}) as the closest honest classification:
 * "used to encrypt/decrypt, kind and identity unspecified". No new mapper model class was created
 * for this batch — the existing generic {@code Algorithm(name, kind, detectionLocation)} concept is
 * sufficient, exactly as it already was for {@code NATIVEPRNG}.
 *
 * <p><b>Modeling decision — static one-shot calls vs. instance depending-rule operations:</b>
 * mirrors the {@code HKDF}/{@code RandomNumberGenerator} static-methods precedent (see {@link
 * DotNetKeyDerivation}, {@link DotNetRandomNumberGenerator}). {@code ProtectedData.Protect}/{@code
 * TryProtect}/{@code Unprotect}/{@code TryUnprotect} and {@code ProtectedMemory.Protect}/{@code
 * Unprotect} are each a complete, self-contained, fully static call with no instance to track — the
 * "algorithm identity" (DPAPI) and the "operation" (encrypt/decrypt) happen at once. Because a
 * detection rule's top-level {@code shouldBeDetectedAs} can only capture one thing (see
 * DETECTION_RULE_STRUCTURE.md), and {@code CipherContext}'s existing translation branches already
 * distinguish a {@code ValueAction} (algorithm identity) from a {@code CipherAction}
 * (encrypt/decrypt functionality) as two independent, mutually exclusive top-level captures, these
 * static calls capture a single merged {@code ValueActionFactory<>("DPAPI_PROTECT")} / {@code
 * ValueActionFactory<>("DPAPI_UNPROTECT")} value instead. {@code CSharpCipherContextTranslator}
 * then builds the composite node directly (the {@code DPAPI} {@code Algorithm} node with an {@code
 * Encrypt}/{@code Decrypt} functionality child already attached) — the same "single detected string
 * encodes both identity and purpose" idiom already used elsewhere in this codebase (e.g. {@code
 * JavaKeyContextTranslator}'s {@code algo.put(new KeyGeneration(detectionLocation))} pattern).
 *
 * <p>By contrast, {@code DpapiDataProtector} <em>does</em> have a real tracked instance (created
 * via {@code new DpapiDataProtector(...)}), so it follows the AES-family creation/depending-rule
 * pattern instead (see {@link DotNetAES}): the constructor is a top-level rule capturing the {@code
 * "DPAPI"} identity, with the instance {@code Protect}/{@code Unprotect} calls as depending rules
 * capturing {@code CipherActionFactory<>(CipherAction.Action.ENCRYPT/DECRYPT)} — translated as
 * children of the already-identified {@code DPAPI} node by the existing (unmodified) {@code
 * CipherAction} branch of {@code CSharpCipherContextTranslator}.
 *
 * <p>As with every other file in this rule set, the ANTLR4-based C# engine cannot resolve parameter
 * types (see {@code CSharpLanguageTranslation}), so all overloads that only differ by {@code
 * byte[]} vs. {@code ReadOnlySpan<byte>}/{@code Span<byte>}, or by the presence of an output-buffer
 * / {@code out} parameter, are collapsed into a single {@code withAnyParameters()} rule per method
 * name — exactly like {@code TryEncryptCbc} etc. in {@link DotNetAES}.
 *
 * <p><b>Known gap — {@code DataProtectionScope}/{@code MemoryProtectionScope} parameter, and {@code
 * DpapiDataProtector.Scope} property setter, are not decoded:</b> unlike {@code CipherMode}/{@code
 * PaddingMode} (decoded by {@code AES_SET_MODE}/{@code AES_SET_PADDING} in {@link DotNetAES}
 * because the mapper model already has generic, cross-library {@code Mode}/{@code Padding} concepts
 * that {@code CipherMode.CBC}/{@code PaddingMode.PKCS7} map onto), {@code DataProtectionScope}
 * ({@code CurrentUser}/{@code LocalMachine}) and {@code MemoryProtectionScope} ({@code
 * SameProcess}/{@code CrossProcess}/{@code SameLogon}) describe <em>who can decrypt the data</em>
 * (a key-custody / access-scope concept), not a cipher mode, padding, or any other concept the
 * mapper model currently represents. Forcing it through {@code ModeFactory} or a similar existing
 * factory would silently mislabel an access-scope value as a block-cipher mode once it reaches
 * {@code JcaModeMapper}, which would not recognize e.g. {@code "CurrentUser"} and would just drop
 * it — arguably worse than not capturing it at all. The engine <em>can</em> technically resolve
 * these enum member-access expressions to their member name (see {@code
 * CSharpDetectionEngine#resolveValues}, which handles {@code CSharpMemberAccessTree} generically,
 * not only for {@code Mode}/{@code Padding}), so this is a genuine modeling gap — not an engine
 * limitation — flagged here per the "document, don't force" principle rather than silently deciding
 * one way. The scope parameter position is still captured (via {@code MethodMatcher.ANY},
 * uninterpreted) so the rule's parameter arity/shape stays accurate; only its value is left
 * uncaptured. For the same reason, {@code DpapiDataProtector}'s {@code appName}/{@code
 * primaryPurpose}/{@code specificPurpose} constructor arguments (arbitrary caller-chosen strings,
 * not cryptographic identifiers) and its {@code Scope} property setter are not decoded either.
 */
@SuppressWarnings("java:S1192")
public final class DotNetProtectedData {

    private DotNetProtectedData() {
        // nothing
    }

    // =========================================================================
    // ProtectedData — static-only class. Each static call is both the "creation" and
    // the "operation" at once (see class javadoc "Modeling decision").
    // =========================================================================

    // ProtectedData.Protect(byte[] userData, byte[] optionalEntropy, DataProtectionScope scope)
    // / Protect(ReadOnlySpan<byte>, DataProtectionScope, ReadOnlySpan<byte>)
    // / Protect(ReadOnlySpan<byte>, DataProtectionScope, Span<byte>, ReadOnlySpan<byte>)
    private static final IDetectionRule<CSharpTree> PROTECTED_DATA_PROTECT =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("ProtectedData")
                    .forMethods("Protect")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DPAPI_PROTECT"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // ProtectedData.Unprotect(...) — same overload shapes as Protect, mirrored.
    private static final IDetectionRule<CSharpTree> PROTECTED_DATA_UNPROTECT =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("ProtectedData")
                    .forMethods("Unprotect")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DPAPI_UNPROTECT"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // ProtectedData.TryProtect(ReadOnlySpan<byte>, DataProtectionScope, Span<byte>, out int,
    // ReadOnlySpan<byte>)
    private static final IDetectionRule<CSharpTree> PROTECTED_DATA_TRY_PROTECT =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("ProtectedData")
                    .forMethods("TryProtect")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DPAPI_PROTECT"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // ProtectedData.TryUnprotect(...) — mirrors TryProtect.
    private static final IDetectionRule<CSharpTree> PROTECTED_DATA_TRY_UNPROTECT =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("ProtectedData")
                    .forMethods("TryUnprotect")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DPAPI_UNPROTECT"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // =========================================================================
    // ProtectedMemory — static-only class. No Try* overloads are published for this class.
    // =========================================================================

    // ProtectedMemory.Protect(byte[] userData, MemoryProtectionScope scope)
    private static final IDetectionRule<CSharpTree> PROTECTED_MEMORY_PROTECT =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("ProtectedMemory")
                    .forMethods("Protect")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DPAPI_PROTECT"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // ProtectedMemory.Unprotect(byte[] encryptedData, MemoryProtectionScope scope)
    private static final IDetectionRule<CSharpTree> PROTECTED_MEMORY_UNPROTECT =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("ProtectedMemory")
                    .forMethods("Unprotect")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DPAPI_UNPROTECT"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // =========================================================================
    // DpapiDataProtector — real tracked instance (new DpapiDataProtector(...)), so this follows
    // the AES-family creation/depending-rule pattern instead of the static one-shot pattern above
    // (see class javadoc).
    // =========================================================================

    // protector.Protect(byte[] userData) — instance method inherited from DataProtector.
    private static final IDetectionRule<CSharpTree> DPAPI_INSTANCE_PROTECT =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("Protect")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.ENCRYPT))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // protector.Unprotect(byte[] encryptedData) — instance method inherited from DataProtector.
    private static final IDetectionRule<CSharpTree> DPAPI_INSTANCE_UNPROTECT =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("Unprotect")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.DECRYPT))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    private static final List<IDetectionRule<CSharpTree>> DPAPI_INSTANCE_DEPENDING_RULES =
            List.of(DPAPI_INSTANCE_PROTECT, DPAPI_INSTANCE_UNPROTECT);

    // new DpapiDataProtector(appName, primaryPurpose, specificPurpose...) — single constructor
    // overload, but with a params array (variable arity), so withAnyParameters() is used exactly
    // like the AesCng / SP800108HmacCounterKdf precedents for the same reason.
    private static final IDetectionRule<CSharpTree> DPAPI_DATA_PROTECTOR_CTOR =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("DpapiDataProtector")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DPAPI"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(DPAPI_INSTANCE_DEPENDING_RULES);

    @Nonnull
    public static List<IDetectionRule<CSharpTree>> rules() {
        return List.of(
                PROTECTED_DATA_PROTECT,
                PROTECTED_DATA_UNPROTECT,
                PROTECTED_DATA_TRY_PROTECT,
                PROTECTED_DATA_TRY_UNPROTECT,
                PROTECTED_MEMORY_PROTECT,
                PROTECTED_MEMORY_UNPROTECT,
                DPAPI_DATA_PROTECTOR_CTOR);
    }
}
