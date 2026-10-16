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
package com.ibm.engine.language.csharp;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.detection.Handler;
import com.ibm.engine.detection.IDetectionEngine;
import com.ibm.engine.detection.MethodDetection;
import com.ibm.engine.detection.ResolvedValue;
import com.ibm.engine.detection.TraceSymbol;
import com.ibm.engine.detection.ValueDetection;
import com.ibm.engine.language.csharp.tree.CSharpArgument;
import com.ibm.engine.language.csharp.tree.CSharpArrayCreationTree;
import com.ibm.engine.language.csharp.tree.CSharpBinaryExpressionTree;
import com.ibm.engine.language.csharp.tree.CSharpBlockTree;
import com.ibm.engine.language.csharp.tree.CSharpIdentifierTree;
import com.ibm.engine.language.csharp.tree.CSharpLiteralTree;
import com.ibm.engine.language.csharp.tree.CSharpMemberAccessTree;
import com.ibm.engine.language.csharp.tree.CSharpMethodInvocationTree;
import com.ibm.engine.language.csharp.tree.CSharpObjectCreationTree;
import com.ibm.engine.language.csharp.tree.CSharpScope;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.engine.language.csharp.tree.CSharpVariable;
import com.ibm.engine.model.factory.IValueFactory;
import com.ibm.engine.model.factory.SizeFactory;
import com.ibm.engine.rule.DetectableParameter;
import com.ibm.engine.rule.DetectionRule;
import com.ibm.engine.rule.MethodDetectionRule;
import com.ibm.engine.rule.Parameter;
import java.util.Collections;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Detection engine implementation for C#.
 *
 * <p>Walks a {@link CSharpBlockTree} looking for {@link CSharpMethodInvocationTree} and {@link
 * CSharpObjectCreationTree} nodes that match the active detection rule, then emits detections and
 * resolves argument values.
 *
 * <p>Symbol resolution is syntactic, not semantic: ANTLR4 provides no type inference, so this class
 * leans entirely on the {@link CSharpScope} symbol table {@code CSharpTreeConverter} builds while
 * converting the parse tree (locals, {@code const}s, and parameters — see {@link CSharpVariable}).
 * A value is resolved only when it is <em>syntactically certain</em>: a literal, a variable with
 * exactly one assignment whose initializer itself resolves, a {@code const}, a class field the
 * class never reassigns, a formal parameter whose callers within the same file all pass the same
 * expression, or a call to a method of the same file that has exactly one return value (the last
 * two are prepared by {@code CSharpTreeConverter}'s post-passes). Everything else — a parameter fed
 * from another file, a variable reassigned to conflicting values, a branch-dependent expression —
 * resolves to nothing rather than to a guess.
 *
 * <p>This "no value is better than a wrong one" principle is enforced by five guards, referenced by
 * ID throughout this class:
 *
 * <ul>
 *   <li><b>G1</b> — {@link #resolveIdentifier} never falls back to an identifier's own spelling as
 *       its value (the previous behaviour that made {@code aes.KeySize = keySize;} silently resolve
 *       "keySize" as if it were a value).
 *   <li><b>G2</b> — a {@link SizeFactory} (KeySize, BlockSize, TagSize, ...) may only ever consume
 *       an actual {@code Integer} (a literal, a resolved constant, or an array length); it must
 *       never be handed a {@code String} to convert via byte-length, which is how a variable name
 *       or an unrelated string previously turned into a bogus key length. Every other factory may
 *       still resolve an array's length as an Integer (or a member-access name as a String) — this
 *       filter is specifically about what a size factory may consume, not about hiding those shapes
 *       from everything else, since e.g. a constant-valued {@code ModeFactory("CBC")} attached to a
 *       {@code byte[]} parameter needs only the argument's location, not its value.
 *   <li><b>G3</b> — enforced one layer up, and in two places. For a rule whose parameters are
 *       positional it is {@code CSharpLanguageTranslation#getMethodParameterTypes}, where a rule
 *       that declares a concrete parameter type rejects an argument whose syntactic type is known
 *       and incompatible. For a rule whose parameters are named — which is how the .NET rule set
 *       declares everything it captures — it is {@link CSharpNamedArgumentBinder}, which decides
 *       <em>which</em> argument fills each declared parameter, by keyword, then by position, then
 *       by unique declared type, and rejects the call outright when a required parameter cannot be
 *       filled. That is what places a value correctly when two overloads of the same arity order
 *       their parameters differently, and what keeps an argument that cannot be the declared type
 *       from being read as it.
 *   <li><b>G4</b> — {@link #resolveIdentifier} refuses to resolve a local variable that was
 *       assigned more than once with differing values (see {@link
 *       CSharpVariable#withAdditionalAssignment}).
 *   <li><b>G5</b> — {@link #isInvocationOnVariable} refuses to match an invocation that textually
 *       precedes the creation of the variable it is supposedly a member of. It does resolve a chain
 *       of plain alias assignments ({@code var alias = aes;}) via {@link #resolveAliasChain}, so a
 *       depending rule written for the creation still fires on the alias — but only for an alias
 *       assigned exactly once, for the same reason as G4.
 * </ul>
 *
 * <p>One place deliberately adds recall rather than removing it: a parameter that declares both a
 * value factory and depending rules falls back to those rules when its own resolution found
 * nothing. That covers an argument position holding either a constant or a call that produces the
 * same kind of value, as {@code ECDsa.Create} does with {@code ECCurve.NamedCurves.nistP256} and
 * {@code ECCurve.CreateFromFriendlyName("secp256k1")}. Because the fallback runs only after
 * resolution came up empty, it can add a value where there was none but never a second, competing
 * one.
 */
@SuppressWarnings("java:S3776")
public final class CSharpDetectionEngine implements IDetectionEngine<CSharpTree, CSharpSymbol> {

    @Nonnull
    private final DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
            detectionStore;

    @Nonnull
    private final Handler<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> handler;

    public CSharpDetectionEngine(
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull Handler<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> handler) {
        this.detectionStore = detectionStore;
        this.handler = handler;
    }

    @Override
    public void run(@Nonnull CSharpTree tree) {
        run(TraceSymbol.createStart(), tree);
    }

    @Override
    public void run(@Nonnull TraceSymbol<CSharpSymbol> traceSymbol, @Nonnull CSharpTree tree) {
        // A depending rule whose receiver could not be resolved matches nothing.
        //
        // The receiver guards below only fire for State.SYMBOL, so a NO_SYMBOL trace symbol used
        // to fall through them and offer every statement of the enclosing block to the depending
        // rules. Because operation rules in this module match the receiver as MethodMatcher.ANY
        // (there is no semantic type resolution to narrow it), nothing else stopped an unrelated
        // statement from being accepted: an unassigned Aes.Create() followed by
        // "unrelated.KeySize = 4096" on a different object produced a fabricated AES-4096. Java,
        // Python and Go never hit this because they resolve receiver types and name them
        // concretely, which is their second line of defence.
        //
        // NO_SYMBOL reaches here only from DetectionStore#getAssignedTraceSymbol, i.e. a creation
        // this engine could not tie to a named variable. Parameter-attached depending rules are
        // unaffected: this module dispatches them with Scope.EXPRESSION, which runs them on the
        // argument expression itself and never passes a trace symbol through here. State.DIFFERENT
        // cannot reach this path either, as it is only produced by the parameter-symbol methods.
        // Trading a missing value for a wrong one is the intended direction: a fabricated key size
        // in a bill of materials is worse than an absent one.
        if (traceSymbol.is(TraceSymbol.State.NO_SYMBOL)) {
            return;
        }
        if (tree instanceof CSharpBlockTree blockTree) {
            for (CSharpTree statement : blockTree.getStatements()) {
                processStatement(traceSymbol, statement);
            }
        } else if (tree instanceof CSharpMethodInvocationTree invocation) {
            if (traceSymbol.is(TraceSymbol.State.SYMBOL)
                    && !isInvocationOnVariable(invocation, traceSymbol)) {
                return;
            }
            handler.addCallToCallStack(invocation, detectionStore.getScanContext());
            if (detectionStore
                    .getDetectionRule()
                    .match(invocation, handler.getLanguageSupport().translation())) {
                analyseMethodInvocation(invocation);
            }
        } else if (tree instanceof CSharpObjectCreationTree creation) {
            if (traceSymbol.is(TraceSymbol.State.SYMBOL)
                    && !isInitForVariable(creation, traceSymbol)) {
                return;
            }
            handler.addCallToCallStack(creation, detectionStore.getScanContext());
            if (detectionStore
                    .getDetectionRule()
                    .match(creation, handler.getLanguageSupport().translation())) {
                analyseObjectCreation(creation);
            }
        }
    }

    /**
     * Dispatches a single statement within a block for detection.
     *
     * <p>When {@code traceSymbol} has state {@link TraceSymbol.State#SYMBOL} (i.e. we are scanning
     * for depending rules on a tracked variable), only statements that are invocations on that
     * variable are processed.
     */
    private void processStatement(
            @Nonnull TraceSymbol<CSharpSymbol> traceSymbol, @Nonnull CSharpTree statement) {
        if (statement instanceof CSharpMethodInvocationTree invocation) {
            if (traceSymbol.is(TraceSymbol.State.SYMBOL)
                    && !isInvocationOnVariable(invocation, traceSymbol)) {
                return;
            }
            handler.addCallToCallStack(invocation, detectionStore.getScanContext());
            if (detectionStore
                    .getDetectionRule()
                    .match(invocation, handler.getLanguageSupport().translation())) {
                analyseMethodInvocation(invocation);
            }
        } else if (statement instanceof CSharpObjectCreationTree creation) {
            if (traceSymbol.is(TraceSymbol.State.SYMBOL)
                    && !isInitForVariable(creation, traceSymbol)) {
                return;
            }
            handler.addCallToCallStack(creation, detectionStore.getScanContext());
            if (detectionStore
                    .getDetectionRule()
                    .match(creation, handler.getLanguageSupport().translation())) {
                analyseObjectCreation(creation);
            }
        }
    }

    // -------------------------------------------------------------------------
    // Invocation / creation analysis
    // -------------------------------------------------------------------------

    private void analyseMethodInvocation(@Nonnull CSharpMethodInvocationTree invocation) {
        analyse(invocation, invocation.getArguments());
    }

    private void analyseObjectCreation(@Nonnull CSharpObjectCreationTree creation) {
        analyse(creation, creation.getArguments());
    }

    /**
     * Emits the initial method detection (when applicable) and processes the call's parameters.
     *
     * <p>When the rule declares any named parameter, the arguments are bound first through {@link
     * DetectionStore#bindNamedArguments} — rejecting the call (no detection emitted at all) if a
     * required named argument is absent — before the root {@link MethodDetection} is emitted. This
     * mirrors {@code PythonDetectionEngine#analyseExpression}.
     */
    @SuppressWarnings("unchecked")
    private void analyse(@Nonnull CSharpTree tree, @Nonnull List<CSharpArgument> arguments) {
        if (detectionStore.getDetectionRule().is(MethodDetectionRule.class)) {
            detectionStore.onReceivingNewDetection(new MethodDetection<>(tree, null));
            return;
        }
        DetectionRule<CSharpTree> detectionRule =
                (DetectionRule<CSharpTree>) detectionStore.getDetectionRule();

        final Optional<Map<Integer, CSharpTree>> bindings;
        if (detectionRule.hasNamedMethodParameters()) {
            bindings = detectionStore.bindNamedArguments(tree);
            if (bindings.isEmpty()) {
                return;
            }
        } else {
            bindings = Optional.empty();
        }

        if (detectionRule.actionFactory() != null) {
            detectionStore.onReceivingNewDetection(new MethodDetection<>(tree, null));
        }

        for (Parameter<CSharpTree> parameter : detectionRule.parameters()) {
            final CSharpTree expression;
            if (bindings.isPresent()) {
                expression = bindings.get().get(parameter.getIndex());
            } else if (parameter.getIndex() < arguments.size()) {
                expression = arguments.get(parameter.getIndex()).value();
            } else {
                expression = null;
            }
            if (expression != null) {
                processParameter(parameter, expression, tree);
            }
        }
    }

    @SuppressWarnings("unchecked")
    private void processParameter(
            @Nonnull Parameter<CSharpTree> parameter,
            @Nonnull CSharpTree expression,
            @Nonnull CSharpTree parentTree) {
        if (parameter.is(DetectableParameter.class)) {
            DetectableParameter<CSharpTree> detectable =
                    (DetectableParameter<CSharpTree>) parameter;
            List<ResolvedValue<Object, CSharpTree>> resolved =
                    resolveValuesInInnerScope(
                            Object.class, expression, detectable.getiValueFactory());
            if (resolved.isEmpty()) {
                resolveValuesInOuterScope(expression, detectable);
                // A parameter that declares both a value factory and depending rules falls back to
                // those rules when its own resolution found nothing. Java and Python treat the two
                // as mutually exclusive, which forces a choice for an argument position that may
                // hold either a constant or a call producing the same kind of value — ECDsa.Create
                // takes ECCurve.NamedCurves.nistP256 or ECCurve.CreateFromFriendlyName("secp256k1")
                // in the same slot. Running the depending rules only after resolution came up empty
                // keeps the two from ever both firing, so this can add a value where there was
                // none but can never produce a second, competing one.
                if (!parameter.getDetectionRules().isEmpty()) {
                    dispatchDependingParameter(parameter, expression);
                }
            } else {
                resolved.stream()
                        .map(rv -> new ValueDetection<>(rv, detectable, parentTree, parentTree))
                        .forEach(detectionStore::onReceivingNewDetection);
            }
        } else if (!parameter.getDetectionRules().isEmpty()) {
            dispatchDependingParameter(parameter, expression);
        }
    }

    private void dispatchDependingParameter(
            @Nonnull Parameter<CSharpTree> parameter, @Nonnull CSharpTree expression) {
        if (expression instanceof CSharpMethodInvocationTree invocation) {
            detectionStore.onDetectedDependingParameter(
                    parameter, invocation, DetectionStore.Scope.EXPRESSION);
        } else if (expression instanceof CSharpObjectCreationTree creation) {
            detectionStore.onDetectedDependingParameter(
                    parameter, creation, DetectionStore.Scope.EXPRESSION);
        } else {
            detectionStore.onDetectedDependingParameter(
                    parameter, expression, DetectionStore.Scope.EXPRESSION);
        }
    }

    // -------------------------------------------------------------------------
    // Value resolution
    // -------------------------------------------------------------------------

    @Nonnull
    @Override
    public <O> List<ResolvedValue<O, CSharpTree>> resolveValuesInInnerScope(
            @Nonnull Class<O> clazz,
            @Nonnull CSharpTree expression,
            @Nullable IValueFactory<CSharpTree> valueFactory) {
        Set<Object> resolving = Collections.newSetFromMap(new IdentityHashMap<>());
        List<ResolvedValue<O, CSharpTree>> resolved =
                resolveValues(clazz, expression, valueFactory, resolving);
        if (isSizeFactory(valueFactory)) {
            // G2: a size factory (KeySize, BlockSize, TagSize, ...) may only ever receive an actual
            // Integer. Applied once here, at the point results leave resolution, rather than at
            // each tree-shape branch below, so it uniformly covers every path a String could reach
            // this point from (an identifier resolving to a string constant, a member-access name,
            // ...) without blocking those same shapes for any other (non-size) factory — that
            // distinction is what makes G2 precise instead of a blanket "arrays/strings never
            // resolve" rule, which would have wrongly suppressed constant-valued factories (e.g.
            // ModeFactory("CBC")) attached to a byte[] parameter.
            return resolved.stream().filter(rv -> rv.value() instanceof Integer).toList();
        }
        return resolved;
    }

    @Nonnull
    @SuppressWarnings("unchecked")
    private <O> List<ResolvedValue<O, CSharpTree>> resolveValues(
            @Nonnull Class<O> clazz,
            @Nonnull CSharpTree tree,
            @Nullable IValueFactory<CSharpTree> valueFactory,
            @Nonnull Set<Object> resolving) {

        if (tree instanceof CSharpLiteralTree literal) {
            return resolveLiteral(clazz, literal);
        }

        if (tree instanceof CSharpIdentifierTree identifier) {
            return resolveIdentifier(clazz, identifier, valueFactory, resolving);
        }

        if (tree instanceof CSharpMemberAccessTree memberAccess) {
            if (clazz == String.class || clazz == Object.class) {
                return List.of(new ResolvedValue<>((O) memberAccess.getMemberName(), tree));
            }
            return Collections.emptyList();
        }

        if (tree instanceof CSharpArrayCreationTree arrayCreation) {
            // Mirrors the Java engine's NEW_ARRAY handling: an array's length/element-count is
            // resolved as an Integer regardless of which factory asked — G2 (above) is what stops a
            // SizeFactory from ever seeing a String, and every other factory either wants an
            // Integer
            // too or simply ignores an argument it did not ask for (e.g. a constant-valued
            // ModeFactory("CBC") does not look at the resolved value at all).
            return resolveArrayCreationSize(clazz, arrayCreation, valueFactory, resolving);
        }

        if (tree instanceof CSharpBinaryExpressionTree binary) {
            return resolveBinaryExpression(clazz, binary, resolving);
        }

        if (tree instanceof CSharpMethodInvocationTree invocation
                && invocation.getResolvedReturnValue() != null) {
            // A call to a method of the same file that has exactly one return value — resolve to
            // that value (`RSA.Create(GetKeySize())`). The return expression carries the callee's
            // own scope, so its constants and fields resolve correctly.
            if (!resolving.add(invocation)) {
                return Collections.emptyList(); // recursive helper — no fixed value
            }
            try {
                return resolveValues(
                        clazz, invocation.getResolvedReturnValue(), valueFactory, resolving);
            } finally {
                resolving.remove(invocation);
            }
        }

        // Invocation/creation/anything else: not a resolvable value at this level — handled instead
        // via dispatchDependingParameter for rules that declared addDependingDetectionRules here.
        return Collections.emptyList();
    }

    @Nonnull
    @SuppressWarnings("unchecked")
    private <O> List<ResolvedValue<O, CSharpTree>> resolveLiteral(
            @Nonnull Class<O> clazz, @Nonnull CSharpLiteralTree literal) {
        Object value =
                switch (literal.getKind()) {
                    case INTEGER -> parseIntOrNull(literal.getValue());
                    case BOOLEAN -> Boolean.valueOf(literal.getValue());
                    case STRING -> literal.getValue();
                    case REAL, CHARACTER, NULL -> null;
                };
        if (value == null) {
            return Collections.emptyList();
        }
        if (clazz == Object.class || clazz.isInstance(value)) {
            return List.of(new ResolvedValue<>((O) value, literal));
        }
        return Collections.emptyList();
    }

    /**
     * Resolves an identifier via {@link CSharpScope} — guards G1 and G4. Never falls back to the
     * identifier's own spelling, and refuses a local variable that has more than one differing
     * assignment.
     */
    @Nonnull
    private <O> List<ResolvedValue<O, CSharpTree>> resolveIdentifier(
            @Nonnull Class<O> clazz,
            @Nonnull CSharpIdentifierTree identifier,
            @Nullable IValueFactory<CSharpTree> valueFactory,
            @Nonnull Set<Object> resolving) {
        CSharpScope scope = identifier.getScope();
        if (scope == null) {
            return Collections.emptyList(); // G1
        }
        CSharpVariable variable = scope.lookup(identifier.getName());
        if (variable == null) {
            return Collections.emptyList(); // G1: unknown/untracked identifier — never guess
        }
        if (variable.kind() == CSharpVariable.Kind.PARAMETER && variable.initializer() == null) {
            // A parameter only has a value when every call site in the same file agreed on one
            // (see CSharpTreeConverter#resolveParametersFromCallSites); otherwise it is unknown.
            return Collections.emptyList();
        }
        if ((variable.kind() == CSharpVariable.Kind.LOCAL
                        || variable.kind() == CSharpVariable.Kind.FIELD)
                && variable.assignmentCount() != 1) {
            return Collections.emptyList(); // G4: no initializer, or conflicting reassignments
        }
        CSharpTree initializer = variable.initializer();
        if (initializer == null) {
            return Collections.emptyList();
        }
        if (!resolving.add(variable)) {
            return Collections.emptyList(); // cycle guard (e.g. `a = b; b = a;`)
        }
        try {
            return resolveValues(clazz, initializer, valueFactory, resolving);
        } finally {
            resolving.remove(variable);
        }
    }

    @Nonnull
    @SuppressWarnings("unchecked")
    private <O> List<ResolvedValue<O, CSharpTree>> resolveArrayCreationSize(
            @Nonnull Class<O> clazz,
            @Nonnull CSharpArrayCreationTree array,
            @Nullable IValueFactory<CSharpTree> valueFactory,
            @Nonnull Set<Object> resolving) {
        if (array.getLengthExpression() != null) {
            // new byte[someExpr] — resolve the size expression, but report the finding location as
            // the array creation itself (matches the Java engine's NEW_ARRAY handling).
            return resolveValues(Object.class, array.getLengthExpression(), valueFactory, resolving)
                    .stream()
                    .filter(resolvedValue -> resolvedValue.value() instanceof Integer)
                    .map(
                            resolvedValue ->
                                    new ResolvedValue<>(
                                            (O) resolvedValue.value(), (CSharpTree) array))
                    .toList();
        }
        if (array.getInitializerElementCount() >= 0) {
            return List.of(
                    new ResolvedValue<>((O) (Integer) array.getInitializerElementCount(), array));
        }
        return Collections.emptyList();
    }

    @Nonnull
    @SuppressWarnings("unchecked")
    private <O> List<ResolvedValue<O, CSharpTree>> resolveBinaryExpression(
            @Nonnull Class<O> clazz,
            @Nonnull CSharpBinaryExpressionTree binary,
            @Nonnull Set<Object> resolving) {
        Optional<Integer> left = resolveIntOperand(binary.getLeft(), resolving);
        Optional<Integer> right = resolveIntOperand(binary.getRight(), resolving);
        if (left.isEmpty() || right.isEmpty()) {
            return Collections.emptyList();
        }
        Integer result =
                switch (binary.getOperator()) {
                    case "+" -> left.get() + right.get();
                    case "-" -> left.get() - right.get();
                    case "*" -> left.get() * right.get();
                    case "/" -> right.get() != 0 ? left.get() / right.get() : null;
                    case "%" -> right.get() != 0 ? left.get() % right.get() : null;
                    default -> null;
                };
        if (result == null || !(clazz == Object.class || clazz.isInstance(result))) {
            return Collections.emptyList();
        }
        return List.of(new ResolvedValue<>((O) result, binary));
    }

    @Nonnull
    private Optional<Integer> resolveIntOperand(
            @Nonnull CSharpTree operand, @Nonnull Set<Object> resolving) {
        // No value factory: arithmetic only ever folds plain numeric operands (literals, resolved
        // identifiers/consts, nested arithmetic) — a member-access or array-length operand has no
        // meaningful arithmetic interpretation here.
        return resolveValues(Integer.class, operand, null, resolving).stream()
                .findFirst()
                .map(ResolvedValue::value);
    }

    @Nullable private static Integer parseIntOrNull(@Nonnull String text) {
        String digits = text.replace("_", "");
        int end = digits.length();
        while (end > 0 && "uUlL".indexOf(digits.charAt(end - 1)) >= 0) {
            end--;
        }
        digits = digits.substring(0, end);
        try {
            if (digits.startsWith("0x") || digits.startsWith("0X")) {
                return Integer.parseInt(digits.substring(2), 16);
            }
            if (digits.startsWith("0b") || digits.startsWith("0B")) {
                return Integer.parseInt(digits.substring(2), 2);
            }
            return Integer.parseInt(digits);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static boolean isSizeFactory(@Nullable IValueFactory<CSharpTree> valueFactory) {
        return valueFactory instanceof SizeFactory;
    }

    @Override
    public void resolveValuesInOuterScope(
            @Nonnull CSharpTree expression, @Nonnull Parameter<CSharpTree> parameter) {
        // No-op by design: unlike Java/Python (which distinguish an "inner" AST scope from an
        // "outer" cross-method scope reached via hooks), the C# scope chain built by
        // CSharpTreeConverter already spans from the innermost flattened block, through enclosing
        // blocks, through the method's own parameters, up to the class's `const` fields — all of
        // it is walked by resolveValuesInInnerScope's identifier lookup. By the time this method is
        // called (inner-scope resolution returned nothing), the value is either behind a method
        // parameter (no inter-procedural resolution — documented gap) or genuinely not
        // syntactically determinable. There is currently no case where a *different* attempt here
        // would find something inner-scope resolution could not.
    }

    @Override
    public <O> void resolveMethodReturnValues(
            @Nonnull Class<O> clazz,
            @Nonnull CSharpTree methodDefinition,
            @Nonnull Parameter<CSharpTree> parameter) {
        // Return value resolution not supported without inter-procedural analysis (documented gap)
    }

    @Nullable @Override
    public <O> ResolvedValue<O, CSharpTree> resolveEnumValue(
            @Nonnull Class<O> clazz,
            @Nonnull CSharpTree enumClassDefinition,
            @Nonnull LinkedList<CSharpTree> selections) {
        // Enum class definition lookup not supported (no semantic model of enum declarations)
        return null;
    }

    // -------------------------------------------------------------------------
    // Symbol tracking
    // -------------------------------------------------------------------------

    @Nonnull
    @Override
    public Optional<TraceSymbol<CSharpSymbol>> getAssignedSymbol(@Nonnull CSharpTree expression) {
        if (expression instanceof CSharpMethodInvocationTree invocation) {
            String assigned = invocation.getAssignedIdentifier();
            if (assigned != null) {
                return Optional.of(
                        TraceSymbol.createFrom(new CSharpSymbol(assigned, invocation.getLine())));
            }
        } else if (expression instanceof CSharpObjectCreationTree creation) {
            String assigned = creation.getAssignedIdentifier();
            if (assigned != null) {
                return Optional.of(
                        TraceSymbol.createFrom(new CSharpSymbol(assigned, creation.getLine())));
            }
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<TraceSymbol<CSharpSymbol>> getMethodInvocationParameterSymbol(
            @Nonnull CSharpTree methodInvocation, @Nonnull Parameter<CSharpTree> parameter) {
        if (methodInvocation instanceof CSharpMethodInvocationTree invocation) {
            List<CSharpArgument> args = invocation.getArguments();
            int idx = parameter.getIndex();
            if (idx >= 0 && idx < args.size()) {
                return Optional.of(TraceSymbol.createWithStateNoSymbol());
            }
            return Optional.of(TraceSymbol.createWithStateDifferent());
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<TraceSymbol<CSharpSymbol>> getNewClassParameterSymbol(
            @Nonnull CSharpTree newClass, @Nonnull Parameter<CSharpTree> parameter) {
        if (newClass instanceof CSharpObjectCreationTree creation) {
            List<CSharpArgument> args = creation.getArguments();
            int idx = parameter.getIndex();
            if (idx >= 0 && idx < args.size()) {
                return Optional.of(TraceSymbol.createWithStateNoSymbol());
            }
            return Optional.of(TraceSymbol.createWithStateDifferent());
        }
        return Optional.empty();
    }

    @Override
    public boolean isInvocationOnVariable(
            CSharpTree methodInvocation, @Nonnull TraceSymbol<CSharpSymbol> variableSymbol) {
        if (!(methodInvocation instanceof CSharpMethodInvocationTree invocation)) {
            return false;
        }
        CSharpSymbol sym = variableSymbol.getSymbol();
        if (sym == null) {
            return false;
        }
        // The objectTypeName holds the receiver — matches when it equals the tracked variable's
        // name, or resolves to it through a chain of alias assignments (`var alias = aes;`).
        String receiver = resolveAliasChain(invocation.getScope(), invocation.getObjectTypeName());
        if (!receiver.equals(sym.getName())) {
            return false;
        }
        // G5: refuse an invocation that textually precedes the creation of the variable it is
        // supposedly a member of — statements in a (possibly block-flattened) CSharpBlockTree are
        // in source order, so this rejects both a stray same-named call written earlier in the
        // method and a call that landed on a since-superseded creation.
        return invocation.getLine() >= sym.getDeclarationLine();
    }

    @Override
    public boolean isInitForVariable(
            CSharpTree newClass, @Nonnull TraceSymbol<CSharpSymbol> variableSymbol) {
        String assignedId = null;
        if (newClass instanceof CSharpMethodInvocationTree invocation) {
            assignedId = invocation.getAssignedIdentifier();
        } else if (newClass instanceof CSharpObjectCreationTree creation) {
            assignedId = creation.getAssignedIdentifier();
        }
        if (assignedId == null) {
            return false;
        }
        CSharpSymbol sym = variableSymbol.getSymbol();
        if (sym == null) {
            return false;
        }
        return resolveAliasChain(newClass.getScope(), assignedId).equals(sym.getName());
    }

    /**
     * Follows a chain of plain alias assignments ({@code var alias = aes;}, {@code var a2 = a1;})
     * back to the variable that actually holds the created object, so a depending rule written for
     * the creation still fires on {@code alias.Mode = ...}.
     *
     * <p>Resolution uses the {@link CSharpScope} symbol table rather than a separate alias map, so
     * it is scope-aware (an alias shadowed in an inner block does not leak out) and subject to the
     * same G4 guard as every other value: an alias assigned more than once is not a reliable alias
     * and is left unresolved. {@code visited} guards against a cycle ({@code a = b; b = a;}).
     */
    @Nonnull
    private static String resolveAliasChain(@Nullable CSharpScope scope, @Nonnull String name) {
        if (scope == null) {
            return name;
        }
        String current = name;
        Set<String> visited = new HashSet<>();
        while (visited.add(current)) {
            CSharpVariable variable = scope.lookup(current);
            if (variable == null
                    || variable.kind() != CSharpVariable.Kind.LOCAL
                    || variable.assignmentCount() != 1
                    || !(variable.initializer() instanceof CSharpIdentifierTree target)) {
                return current;
            }
            current = target.getName();
        }
        return current;
    }

    @Nullable @Override
    public CSharpTree extractArgumentFromMethodCaller(
            @Nonnull CSharpTree methodDefinition,
            @Nonnull CSharpTree methodInvocation,
            @Nonnull CSharpTree methodParameterIdentifier) {
        // Inter-procedural argument mapping not supported (documented gap)
        return null;
    }
}
