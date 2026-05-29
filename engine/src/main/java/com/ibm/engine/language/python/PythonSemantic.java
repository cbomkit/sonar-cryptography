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
package com.ibm.engine.language.python;

import com.ibm.engine.detection.IType;
import com.ibm.engine.detection.ResolvedValue;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.apache.commons.lang3.tuple.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.plugins.python.api.symbols.ClassSymbol;
import org.sonar.plugins.python.api.symbols.Symbol;
import org.sonar.plugins.python.api.symbols.Usage;
import org.sonar.plugins.python.api.tree.Argument;
import org.sonar.plugins.python.api.tree.AssignmentStatement;
import org.sonar.plugins.python.api.tree.BinaryExpression;
import org.sonar.plugins.python.api.tree.CallExpression;
import org.sonar.plugins.python.api.tree.DictionaryLiteral;
import org.sonar.plugins.python.api.tree.DictionaryLiteralElement;
import org.sonar.plugins.python.api.tree.Expression;
import org.sonar.plugins.python.api.tree.ExpressionList;
import org.sonar.plugins.python.api.tree.FunctionDef;
import org.sonar.plugins.python.api.tree.KeyValuePair;
import org.sonar.plugins.python.api.tree.ListLiteral;
import org.sonar.plugins.python.api.tree.Name;
import org.sonar.plugins.python.api.tree.NoneExpression;
import org.sonar.plugins.python.api.tree.NumericLiteral;
import org.sonar.plugins.python.api.tree.ParameterList;
import org.sonar.plugins.python.api.tree.QualifiedExpression;
import org.sonar.plugins.python.api.tree.RegularArgument;
import org.sonar.plugins.python.api.tree.ReturnStatement;
import org.sonar.plugins.python.api.tree.SetLiteral;
import org.sonar.plugins.python.api.tree.Statement;
import org.sonar.plugins.python.api.tree.StringLiteral;
import org.sonar.plugins.python.api.tree.SubscriptionExpression;
import org.sonar.plugins.python.api.tree.Tree;
import org.sonar.plugins.python.api.tree.Tuple;

public final class PythonSemantic {
    private static final Logger LOGGER = LoggerFactory.getLogger(PythonSemantic.class);

    private PythonSemantic() {
        // private
    }

    @Nonnull
    public static <O> List<ResolvedValue<O, Tree>> resolveValues(
            @Nonnull Class<O> clazz,
            @Nonnull Tree tree,
            List<Map<org.sonar.plugins.python.api.tree.Parameter, Argument>> argsMappingList,
            Object subscriptionIndex,
            boolean returnEnclosingParam,
            PythonDetectionEngine detectionEngine) {
        return resolveValues(
                clazz,
                tree,
                new LinkedList<>(argsMappingList),
                subscriptionIndex,
                returnEnclosingParam,
                false,
                detectionEngine,
                new LinkedList<>());
    }

    /**
     * Takes any tree as input and try to resolve its type. Because Python is not strongly typed, it
     * is hard to give a type to any object. For the instance of a class, its type is the "fully
     * qualified" class name, like {@code org.sonar.plugins.MyClass}. For a variable with a built-in
     * type, its type can be {@code int}, {@code float}, {@code str}, {@code list}, {@code dict},
     * {@code set}. For a variable initialized with the result of a function, like {@code v =
     * myClass.func(arg)}, because the function return type can vary dynamically, we take the
     * convention of defining its return type as the "fully qualified" function name, like {@code
     * org.sonar.plugins.MyClass.func}.
     *
     * @param tree - any kind of Tree
     * @return An optional IType representing the type
     */
    @Nonnull
    public static Optional<IType> resolveTreeType(@Nonnull Tree tree) {
        final List<ResolvedValue<Object, Tree>> values =
                resolveValues(
                        Object.class,
                        tree,
                        new LinkedList<>(),
                        null,
                        false,
                        true,
                        null,
                        new LinkedList<>());
        // call would enhance the results
        final List<Tree> results =
                values.stream()
                        .map(ResolvedValue::tree)
                        .collect(java.util.stream.Collectors.toCollection(LinkedList::new));

        if (results.isEmpty()) {
            // Tries (with few hope) to obtain the type from the Symbol, otherwise returns "*"
            // (meaning ANY type)
            if (tree instanceof Name name) {
                Symbol nameSymbol = name.symbol();
                if (nameSymbol instanceof ClassSymbol nameClassSymbol
                        && nameClassSymbol.fullyQualifiedName() != null) {
                    return Optional.of(
                            (String string) ->
                                    Objects.equals(nameClassSymbol.fullyQualifiedName(), string));
                }
            }
            // Otherwise, we accept all types
            return Optional.of((String string) -> true);
        }

        // Obtain the type from the content
        List<IType> typesList = new LinkedList<>();
        for (Tree resultTree : results) {
            switch (resultTree.getKind()) {
                case NAME:
                    final Name nameTree = (Name) resultTree;
                    String fullyQualifiedNameTemp =
                            Optional.ofNullable(nameTree.symbol())
                                    .map(Symbol::fullyQualifiedName)
                                    .orElse(null);
                    if (fullyQualifiedNameTemp != null) {
                        if (nameTree.parent() instanceof FunctionDef) {
                            // When we want to resolve the type of a function definition, we resolve
                            // the type of the invoked object (to be used in
                            // `getInvokedObjectTypeString`)
                            // To do so, we remove the last part (function name) of the function's
                            // fully qualified name
                            int lastDotIndex = fullyQualifiedNameTemp.lastIndexOf(".");
                            lastDotIndex =
                                    lastDotIndex == -1
                                            ? fullyQualifiedNameTemp.length()
                                            : lastDotIndex;
                            fullyQualifiedNameTemp =
                                    fullyQualifiedNameTemp.substring(0, lastDotIndex);
                        }
                        final String fullyQualifiedName = fullyQualifiedNameTemp;
                        typesList.add(
                                (String string) ->
                                        resolveFullyQualifiedNameStringType(
                                                fullyQualifiedName, string));
                    } else {
                        // returning type any
                        typesList.add((String string) -> true);
                    }
                    break;
                case STRING_LITERAL:
                    StringLiteral stringLiteralTree = (StringLiteral) resultTree;
                    typesList.add(
                            (String string) -> stringLiteralTree.type().canBeOrExtend(string));
                    break;
                case NUMERIC_LITERAL:
                    NumericLiteral numberLiteralTree = (NumericLiteral) resultTree;
                    typesList.add(
                            (String string) -> numberLiteralTree.type().canBeOrExtend(string));
                    break;
                case LIST_LITERAL:
                    ListLiteral listLiteralTree = (ListLiteral) resultTree;
                    typesList.add((String string) -> listLiteralTree.type().canBeOrExtend(string));
                    break;
                case DICTIONARY_LITERAL:
                    DictionaryLiteral dictionaryLiteral = (DictionaryLiteral) resultTree;
                    typesList.add(
                            (String string) -> dictionaryLiteral.type().canBeOrExtend(string));
                    break;
                case SET_LITERAL:
                    SetLiteral setLiteral = (SetLiteral) resultTree;
                    typesList.add((String string) -> setLiteral.type().canBeOrExtend(string));
                    break;
                case NONE:
                    typesList.add((String string) -> string.equals("None"));
                    break;
                default:
                    // This case should never be reached
                    LOGGER.debug(
                            "Detected tree type {} used in `resolveTreeType` that is not currently supported",
                            resultTree.getKind());
                    break;
            }
        }

        // If typesList contains more than one type, we return an IType that "accepts" any type that
        // is part of the list
        return Optional.of((String string) -> resolveMultipleTypes(string, typesList));
    }

    /**
     * Returns if the given stringType is accepted by at least one of the IType of typesList. It can
     * be used to implement an IType representing the union of the {@code typesList} of IType(s).
     *
     * @param stringType - a string representing a type to test
     * @param typesList - a list of ITypes
     * @return A boolean, {@code true} if at least one IType in {@code typesList} is of type {@code
     *     stringType}
     */
    private static boolean resolveMultipleTypes(
            @Nonnull String stringType, @Nonnull List<IType> typesList) {
        return typesList.stream().anyMatch(iType -> iType.is(stringType));
    }

    /**
     * Returns if the {@code fullyQualifiedNameStringType} is of type {@code wantedStringType},
     * where {@code wantedStringType} can be written like {@code x.y.z.*} to indicate that we accept
     * any type starting by {@code x.y.z}.
     *
     * @param fullyQualifiedNameStringType - a string representing a type to test
     * @param wantedStringType - a string representing the accepted type(s), that can finish with
     *     {@code .*}
     * @return A boolean, {@code true} if {@code fullyQualifiedNameStringType} is of type {@code
     *     wantedStringType}
     */
    private static boolean resolveFullyQualifiedNameStringType(
            @Nonnull String fullyQualifiedNameStringType, @Nonnull String wantedStringType) {
        boolean result = false;

        // When defining a "type" in `forObjectTypes`, we never include the end (method or class
        // name). To detect `cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicNumbers`, we use
        // `forObjectTypes("cryptography.hazmat.primitives.asymmetric.dsa")`
        // Therefore we also test a `shortenedFullyQualifiedNameStringType` that does not contain
        // the method or class name in it
        // We also test the full original `fullyQualifiedNameStringType` because it is what we
        // expect when defining a "type" in `withMethodParameter`
        String shortenedFullyQualifiedNameStringType = fullyQualifiedNameStringType;
        int lastDotIndex = fullyQualifiedNameStringType.lastIndexOf(".");
        if (lastDotIndex != -1) {
            shortenedFullyQualifiedNameStringType =
                    fullyQualifiedNameStringType.substring(0, lastDotIndex);
        }

        if (wantedStringType.endsWith(".*")) {
            String prefix = wantedStringType.substring(0, wantedStringType.length() - 2);
            result =
                    fullyQualifiedNameStringType.startsWith(prefix)
                            || shortenedFullyQualifiedNameStringType.startsWith(prefix);
        } else {
            result =
                    fullyQualifiedNameStringType.equals(wantedStringType)
                            || shortenedFullyQualifiedNameStringType.equals(wantedStringType);
        }
        return result;
    }

    /**
     * Helper function for extracing the value from NumericLiterals. NumericLiterals can have int,
     * float or string values. The python scanner only cares about ints as indexes of lists. All
     * other numerics will be handled as strings.
     *
     * @param indexLiteralTree parsed NumericLiteral
     * @return Integer object for int values, String otherwise
     */
    private static Object getNumericValue(NumericLiteral indexLiteralTree) {
        String value = indexLiteralTree.valueAsString();
        try {
            return Integer.valueOf(value);
        } catch (NumberFormatException e) {
            // fall thru
        }
        return value;
    }

    /**
     * For a given {@code tree}, this function resolve its associated values by following the chain
     * of function calls and assignments. As its result includes the associated Trees, this function
     * can also be used for type resolution of the given {@code tree}. Various parameters described
     * below allow to change the exact behavior of the function.
     *
     * @param tree - any kind of Tree
     * @param argsMappingList - list storing mappings between function definition parameter names
     *     and their value in function calls in the chain of recursive calls (it should be an empty
     *     list in the initial function call)
     * @param subscriptionIndex - index of the last observed SubscriptionExpression (like {@code
     *     myList[1]} or {@code myDict["abc"]}) in the chain of recursive calls (it should be {@code
     *     null} in the initial function call)
     * @param returnEnclosingParam - when set to true, makes the function return the first parameter
     *     Name tree that it cannot resolve in inner scope (it is useful for outer scope resolution)
     * @param isResolvingType - when set to true, slightly adapt the function for resolving the type
     *     of {@code tree} (in particular, it makes the function return all function function
     *     declaration Name trees in addition to the usual results)
     * @param detectionEngine - instance of the current PythonDetectionEngine (it can be set to null
     *     {@code null} but this will limit the depth of the resolution)
     * @param alreadyResolvedTrees - list storing all recursively vsisited trees to resolve, along
     *     with the last arguments mapping, in order to check if a tree has already been resolved to
     *     avoid infinite loops (it should be an empty list in the initial function call)
     * @return A list of resolved values, composed of the actual resolved values as an Object and
     *     the associated Tree
     */
    @SuppressWarnings("java:S1905")
    @Nonnull
    private static <O> List<ResolvedValue<O, Tree>> resolveValues(
            @Nonnull Class<O> clazz,
            @Nonnull Tree tree,
            @Nonnull
                    LinkedList<Map<org.sonar.plugins.python.api.tree.Parameter, Argument>>
                            argsMappingList,
            Object subscriptionIndex,
            boolean returnEnclosingParam,
            boolean isResolvingType,
            PythonDetectionEngine detectionEngine,
            List<Pair<Tree, Map<org.sonar.plugins.python.api.tree.Parameter, Argument>>>
                    alreadyResolvedTrees) {
        // Checks is the tree to resolve has been previously resolved (and with the same set of
        // arguments)
        // If so, it will lead to an infinite loop, so we return an empty list of results.
        Map<org.sonar.plugins.python.api.tree.Parameter, Argument> map = null;
        if (!argsMappingList.isEmpty()) {
            map = argsMappingList.getLast();
        }
        Pair<Tree, Map<org.sonar.plugins.python.api.tree.Parameter, Argument>> pair =
                Pair.of(tree, map);
        if (alreadyResolvedTrees.contains(pair)) {
            return new LinkedList<>();
        }
        alreadyResolvedTrees.add(pair);

        // Case disjunction depending on the type of Tree
        if (tree.is(Tree.Kind.NAME)) {

            LinkedList<ResolvedValue<O, Tree>> result = new LinkedList<>();
            Name nameTree = (Name) tree;

            // If the symbol is null, we cannot resolve anything
            if (nameTree.symbol() == null) {
                return result;
            }

            List<Usage> usages =
                    new LinkedList<>(Objects.requireNonNull(nameTree.symbol()).usages());

            // We remove all the usages that are declared *after* the current tree, and we remove
            // the usage of the current tree that we are resolving
            // In Python, both when calling a variables or a function, it has to be defined before
            //
            // This filtering using `line()` will not be enough when handling multiple Python
            // files, and should be only applied to the current file
            if (nameTree.firstToken() != null) {
                int currentLine = nameTree.firstToken().line();
                usages.removeIf(
                        usage ->
                                (usage.tree() instanceof Name usageNameTree
                                        && (usageNameTree.equals(nameTree)
                                                || (usageNameTree.firstToken() != null
                                                        && usageNameTree.firstToken().line()
                                                                > currentLine))));
            }

            // If the current Name has no assignment, function declaration or parameter usage, then
            // it is probably and imported class (or function) like `SECP384R1()`
            // In this case, we will have to resolve its name to return "SECP384R1"
            // We keep track of this using the boolean below, that we set to false when there is an
            // assignment, function declaration or parameter usage
            boolean shouldResolveNameContent = true;

            // Resolve all declarations
            if (!usages.isEmpty()) {
                for (Usage usage : usages) {
                    Tree usageTree = usage.tree();
                    if (usageTree instanceof Name usageNameTree) {
                        if (usage.kind() == Usage.Kind.ASSIGNMENT_LHS) {
                            shouldResolveNameContent = false;
                            // In all assignments, the parent of the Name is an ExpressionList,
                            // whose parent is the AssignmentStatement. We then resolve the RHS
                            // (assignedValue), like what is done with the IdentifierTree in Java.
                            Tree parent1 = usageNameTree.parent();
                            if (parent1 != null && parent1.is(Tree.Kind.EXPRESSION_LIST)) {
                                ExpressionList expressionListTree = (ExpressionList) parent1;
                                Tree parent2 = expressionListTree.parent();
                                if (parent2 != null && parent2.is(Tree.Kind.ASSIGNMENT_STMT)) {
                                    AssignmentStatement assignment = (AssignmentStatement) parent2;

                                    Expression assignedValueTree = assignment.assignedValue();

                                    if (assignedValueTree instanceof Tuple tupleTree
                                            && expressionListTree.expressions().size()
                                                    == tupleTree.elements().size()) {
                                        // Special case of a multi-variable assignment `v1, v2 =
                                        // 'a', 'b'`
                                        // We handle here the logic to find the correct assigned
                                        // value (RHS) to resolve (based on which LHS we want to
                                        // resolve)
                                        int nameIndexInTuple =
                                                expressionListTree
                                                        .expressions()
                                                        .indexOf(usageNameTree);
                                        if (nameIndexInTuple >= 0
                                                && nameIndexInTuple < tupleTree.elements().size()) {
                                            // When the name has been found
                                            result.addAll(
                                                    resolveValues(
                                                            clazz,
                                                            tupleTree
                                                                    .elements()
                                                                    .get(nameIndexInTuple),
                                                            argsMappingList,
                                                            subscriptionIndex,
                                                            returnEnclosingParam,
                                                            isResolvingType,
                                                            detectionEngine,
                                                            alreadyResolvedTrees));
                                        }
                                    } else {
                                        // Normal assignment: we resolve the assigned value
                                        result.addAll(
                                                resolveValues(
                                                        clazz,
                                                        assignedValueTree,
                                                        argsMappingList,
                                                        subscriptionIndex,
                                                        returnEnclosingParam,
                                                        isResolvingType,
                                                        detectionEngine,
                                                        alreadyResolvedTrees));
                                    }
                                }
                            }
                        } else if (usage.kind() == Usage.Kind.FUNC_DECLARATION) {
                            // For type resolution, we need to return all function declarations
                            // Indeed, when resolving a call expression like `func(some_var)`, it
                            // can be for two things:
                            //  - Usually, it is to resolve the value or type of the result of the
                            // call expression, which is done by looking at the return statements of
                            // the call expression
                            //  - But in type resolution, it can be to get the
                            // `getInvokedObjectTypeString` of `func`, which we define by convention
                            // as its `fullyQualifiedName` -> therefore, we add all function
                            // declaration trees as results
                            if (isResolvingType) {
                                Optional<O> value = resolveConstant(clazz, usageNameTree);
                                result.addAll(
                                        value.map(
                                                        t ->
                                                                List.of(
                                                                        new ResolvedValue<>(
                                                                                t,
                                                                                (Tree)
                                                                                        usageNameTree)))
                                                .orElse(Collections.emptyList()));
                            }

                            shouldResolveNameContent = false;
                            Tree parent1 = usageNameTree.parent();
                            if (parent1 != null && parent1.is(Tree.Kind.FUNCDEF)) {
                                FunctionDef functionDefTree = (FunctionDef) parent1;
                                for (Statement statementTree :
                                        functionDefTree.body().statements()) {
                                    // We resolve all return statements
                                    if (statementTree instanceof ReturnStatement returnStatementTree
                                            && !returnStatementTree.expressions().isEmpty()) {
                                        if (subscriptionIndex
                                                        instanceof Integer intSubscriptionIndex
                                                && intSubscriptionIndex
                                                        < returnStatementTree
                                                                .expressions()
                                                                .size()) {
                                            // Case where we know the subscription index: we
                                            // resolve the right expression, and we remove the
                                            // subscription index for deeper resolution, now
                                            // that it has been utilized
                                            result.addAll(
                                                    resolveValues(
                                                            clazz,
                                                            returnStatementTree
                                                                    .expressions()
                                                                    .get(intSubscriptionIndex),
                                                            argsMappingList,
                                                            null,
                                                            returnEnclosingParam,
                                                            isResolvingType,
                                                            detectionEngine,
                                                            alreadyResolvedTrees));
                                        } else {
                                            // Case where we don't know the subscription index:
                                            // we resolve everything
                                            for (Expression expressionTree :
                                                    returnStatementTree.expressions()) {
                                                @SuppressWarnings("unchecked")
                                                LinkedList<
                                                                Map<
                                                                        org.sonar.plugins.python.api
                                                                                .tree.Parameter,
                                                                        Argument>>
                                                        argsMappingListClone =
                                                                (LinkedList<
                                                                                Map<
                                                                                        org.sonar
                                                                                                .plugins
                                                                                                .python
                                                                                                .api
                                                                                                .tree
                                                                                                .Parameter,
                                                                                        Argument>>)
                                                                        argsMappingList.clone();
                                                result.addAll(
                                                        resolveValues(
                                                                clazz,
                                                                expressionTree,
                                                                argsMappingListClone,
                                                                subscriptionIndex,
                                                                returnEnclosingParam,
                                                                isResolvingType,
                                                                detectionEngine,
                                                                alreadyResolvedTrees));
                                            }
                                        }
                                    }
                                }
                            }
                        } else if (usage.kind() == Usage.Kind.PARAMETER) {
                            shouldResolveNameContent = false;

                            // In the context of a hook, case where we want to return the function
                            // parameter of the enclosing function as the resolved value.
                            // We check that `argsMappingList.isEmpty()` to make sure that all
                            // possible inner resolutions are done before returning the resolved
                            // value
                            if (returnEnclosingParam && argsMappingList.isEmpty()) {
                                Optional<O> value = resolveConstant(clazz, usageNameTree);
                                return value.map(
                                                t ->
                                                        List.of(
                                                                new ResolvedValue<>(
                                                                        t, (Tree) usageNameTree)))
                                        .orElse(Collections.emptyList());
                            }

                            // Continue the inner resolution if we have a non-empty
                            // `argsMappingList`
                            if (usageNameTree.parent()
                                            instanceof
                                            org.sonar.plugins.python.api.tree.Parameter
                                                    parameterTree
                                    && !argsMappingList.isEmpty()) {
                                Argument argument = argsMappingList.pollLast().get(parameterTree);
                                if (argument instanceof RegularArgument regularArgument) {
                                    result.addAll(
                                            resolveValues(
                                                    clazz,
                                                    regularArgument.expression(),
                                                    argsMappingList,
                                                    subscriptionIndex,
                                                    returnEnclosingParam,
                                                    isResolvingType,
                                                    detectionEngine,
                                                    alreadyResolvedTrees));
                                }
                            }
                        }
                    }
                }
            }

            if (result.isEmpty() && shouldResolveNameContent) {
                // When resolving the name does give standard results, we call `resolveConstant` to
                // resolve the string name of the nameTree
                // This is important because the name of a class (like SECP384R1) or function may
                // carry the information about the used cryptography algorithm
                Optional<O> value = resolveConstant(clazz, nameTree);
                return value.map(t -> List.of(new ResolvedValue<>(t, (Tree) nameTree)))
                        .orElse(Collections.emptyList());
            }

            return result;

        } else if (tree.is(Tree.Kind.QUALIFIED_EXPR)) {
            // Written for a case like `res = TestClass.class_var` where `TestClass.class_var` is
            // the QualifiedExpression, and `class_var = 42` is a static variable of the class
            // `TestClass`. We first try to resolve the `.name()` (here class_var) that in this case
            // returns 42. Otherwise, we try to resolve the qualifier (here TestClass).
            List<ResolvedValue<O, Tree>> result;
            QualifiedExpression qualifiedExpressionTree = (QualifiedExpression) tree;
            result =
                    resolveValues(
                            clazz,
                            qualifiedExpressionTree.name(),
                            argsMappingList,
                            subscriptionIndex,
                            returnEnclosingParam,
                            isResolvingType,
                            detectionEngine,
                            alreadyResolvedTrees);
            if (result.isEmpty()) {
                // If resolving the name gives no result, we resolve the qualifier
                result =
                        resolveValues(
                                clazz,
                                qualifiedExpressionTree.qualifier(),
                                argsMappingList,
                                subscriptionIndex,
                                returnEnclosingParam,
                                isResolvingType,
                                detectionEngine,
                                alreadyResolvedTrees);
            }
            return result;
        } else if (tree.is(Tree.Kind.CALL_EXPR)) {
            // Written for a CallExpression `global_var.bit_count()` where `global_var = 43`. This
            // will resolve the callee, which is here a QualifiedExpression here
            // `global_var.bit_count`.
            // This function also appends `argsMappingList` by adding a new mapping between the
            // parameters of the callee's method definition and the actual values from the call
            // expression
            CallExpression callExpressionTree = (CallExpression) tree;

            HashMap<org.sonar.plugins.python.api.tree.Parameter, Argument> thisMapping =
                    new HashMap<>();
            FunctionDef methodDefinition = getMethodDefinition(callExpressionTree);
            if (methodDefinition == null) {
                // Case where the call expression has either been imported or is a class
                // instantiation, so we resolve its name
                return resolveValues(
                        clazz,
                        callExpressionTree.callee(),
                        argsMappingList,
                        subscriptionIndex,
                        returnEnclosingParam,
                        isResolvingType,
                        detectionEngine,
                        alreadyResolvedTrees);
                // In this case, we cannot do much as we do not have access to the function
                // definition. Maybe a better thing than resolving its name could be to resolve its
                // argument? But then, we still want to resolve class names like `ec.SECP384R1()`
            }
            ParameterList parameterList = methodDefinition.parameters();
            if (parameterList == null
                    || parameterList.nonTuple().size() != callExpressionTree.arguments().size()) {
                return resolveValues(
                        clazz,
                        callExpressionTree.callee(),
                        argsMappingList,
                        subscriptionIndex,
                        returnEnclosingParam,
                        isResolvingType,
                        detectionEngine,
                        alreadyResolvedTrees);
            }
            for (org.sonar.plugins.python.api.tree.Parameter parameter :
                    parameterList
                            .nonTuple()) { // TODO: Handle tuple case when using parameterList.all()
                if (detectionEngine != null) {
                    Argument argument =
                            (Argument)
                                    detectionEngine.extractArgumentFromMethodCaller(
                                            methodDefinition,
                                            callExpressionTree,
                                            Objects.requireNonNull(parameter.name()));
                    thisMapping.put(parameter, argument);
                }
            }
            argsMappingList.add(thisMapping);
            return resolveValues(
                    clazz,
                    callExpressionTree.callee(),
                    argsMappingList,
                    subscriptionIndex,
                    returnEnclosingParam,
                    isResolvingType,
                    detectionEngine,
                    alreadyResolvedTrees);

        } else if (tree.is(Tree.Kind.TUPLE)) {
            List<ResolvedValue<O, Tree>> result = new LinkedList<>();
            Tuple tupleTree = (Tuple) tree;
            if (subscriptionIndex instanceof Integer intSubscriptionIndex
                    && intSubscriptionIndex < tupleTree.elements().size()) {
                // Resolve the right tuple when there is a `subscriptionIndex`
                result.addAll(
                        resolveValues(
                                clazz,
                                tupleTree.elements().get(intSubscriptionIndex),
                                argsMappingList,
                                null,
                                returnEnclosingParam,
                                isResolvingType,
                                detectionEngine,
                                alreadyResolvedTrees));
            } else {
                // If there is no valid `subscriptionIndex`, resolve all the elements of the tuple
                for (Expression tupleMemberTree : tupleTree.elements()) {
                    result.addAll(
                            resolveValues(
                                    clazz,
                                    tupleMemberTree,
                                    argsMappingList,
                                    subscriptionIndex,
                                    returnEnclosingParam,
                                    isResolvingType,
                                    detectionEngine,
                                    alreadyResolvedTrees));
                }
            }
            return result;
        } else if (tree.is(Tree.Kind.SUBSCRIPTION)) {
            LinkedList<ResolvedValue<O, Tree>> result = new LinkedList<>();

            SubscriptionExpression subscriptionExpressionTree = (SubscriptionExpression) tree;
            List<Expression> subscriptionIndexList =
                    subscriptionExpressionTree.subscripts().expressions();
            if (subscriptionIndexList.size() == 1) {
                Expression currentSubscriptionIndex = subscriptionIndexList.get(0);

                // The index may not be immediately an int or a string: there can be intermediary
                // assignments, that we resolve. Keep the current argument mappings so an index that
                // is a parameter of the enclosing function can be resolved from the call context.
                List<ResolvedValue<O, Tree>> resolvedSubscriptionIndexList =
                        resolveValues(
                                clazz,
                                currentSubscriptionIndex,
                                new LinkedList<>(argsMappingList),
                                null,
                                returnEnclosingParam,
                                false,
                                detectionEngine,
                                alreadyResolvedTrees);

                for (ResolvedValue<O, Tree> resolvedValue : resolvedSubscriptionIndexList) {
                    Tree resolvedSubscriptionIndex = resolvedValue.tree();

                    if (resolvedSubscriptionIndex instanceof NumericLiteral indexLiteralTree) {
                        Object index = getNumericValue(indexLiteralTree);
                        result.addAll(
                                resolveValues(
                                        clazz,
                                        subscriptionExpressionTree.object(),
                                        new LinkedList<>(argsMappingList),
                                        index,
                                        returnEnclosingParam,
                                        isResolvingType,
                                        detectionEngine,
                                        alreadyResolvedTrees));
                    } else if (resolvedSubscriptionIndex
                            instanceof StringLiteral indexLiteralTree) {
                        String index = (String) (indexLiteralTree.trimmedQuotesValue());
                        List<ResolvedValue<O, Tree>> resolveDictResult =
                                resolveValues(
                                        clazz,
                                        subscriptionExpressionTree.object(),
                                        new LinkedList<>(argsMappingList),
                                        index,
                                        returnEnclosingParam,
                                        isResolvingType,
                                        detectionEngine,
                                        alreadyResolvedTrees);
                        if (resolveDictResult.isEmpty() && !isResolvingType) {
                            // Very special case: if the last result is the
                            // `subscriptionExpressionTree.object()`, it means that the above
                            // `resolveValues` operation was not successful.
                            // Therefore, we resolve the value ["key"] because it carries more
                            // information than the name of the dictionary
                            // The condition `!isResolvingType` prevents this rule from happening
                            // during type resolution, otherwise it would return the unrelated
                            // String type of the `indexLiteralTree`
                            result.add(resolvedValue);
                        } else {
                            // Otherwise, it means that we have successfully resolved
                            // `subscriptionExpressionTree.object()`
                            result.addAll(resolveDictResult);
                        }
                    } else if (returnEnclosingParam && resolvedSubscriptionIndex instanceof Name) {
                        // Case of a subscription `struct[some_var]` where some_var is an argument
                        // of the current enclosing function.
                        // In the case of outer scope resolution with returnEnclosingParam set to
                        // true, we return this argument Name.
                        result.addAll(
                                resolveValues(
                                        clazz,
                                        resolvedSubscriptionIndex,
                                        argsMappingList,
                                        subscriptionIndex,
                                        returnEnclosingParam,
                                        isResolvingType,
                                        detectionEngine,
                                        alreadyResolvedTrees));
                    }
                }
            } else {
                // If the subscription index was not resolved, we resolve everything
                result.addAll(
                        resolveValues(
                                clazz,
                                subscriptionExpressionTree.object(),
                                argsMappingList,
                                subscriptionIndex,
                                returnEnclosingParam,
                                isResolvingType,
                                detectionEngine,
                                alreadyResolvedTrees));
            }
            return result;
        } else if (tree.is(Tree.Kind.LIST_LITERAL)) {
            LinkedList<ResolvedValue<O, Tree>> result = new LinkedList<>();

            ListLiteral listLiteralTree = (ListLiteral) tree;
            List<Expression> listExpressions = listLiteralTree.elements().expressions();
            if (!listExpressions.isEmpty()
                    && subscriptionIndex instanceof Integer intSubscriptionIndex
                    && intSubscriptionIndex < listExpressions.size()) {
                // Case where the list is not empty and we know the subscription index: we resolve
                // the right expression, and we remove the subscription index for future
                // resolutions, now that it has been utilized
                result.addAll(
                        resolveValues(
                                clazz,
                                listExpressions.get(intSubscriptionIndex),
                                argsMappingList,
                                null,
                                returnEnclosingParam,
                                isResolvingType,
                                detectionEngine,
                                alreadyResolvedTrees));
            } else {
                // Case where we don't know the subscription index, or it is not valid: we resolve
                // everything
                for (Expression expressionTree : listExpressions) {
                    result.addAll(
                            resolveValues(
                                    clazz,
                                    expressionTree,
                                    argsMappingList,
                                    subscriptionIndex,
                                    returnEnclosingParam,
                                    isResolvingType,
                                    detectionEngine,
                                    alreadyResolvedTrees));
                }
            }
            return result;
        } else if (tree.is(Tree.Kind.DICTIONARY_LITERAL)) {
            LinkedList<ResolvedValue<O, Tree>> result = new LinkedList<>();

            DictionaryLiteral dictionaryLiteralTree = (DictionaryLiteral) tree;
            List<DictionaryLiteralElement> listElements = dictionaryLiteralTree.elements();
            boolean keyResolved = false;
            if (subscriptionIndex instanceof String) {
                for (DictionaryLiteralElement dictionaryLiteralElement : listElements) {
                    if (dictionaryLiteralElement instanceof KeyValuePair keyValuePairTree
                            && keyValuePairTree.key() instanceof StringLiteral keyLiteral
                            && keyLiteral.trimmedQuotesValue().equals(subscriptionIndex)) {
                        // Case where we know the subscription index: we resolve the right
                        // expression, and we remove the subscription index for future resolutions,
                        // now that it has been utilized
                        keyResolved = true;
                        result.addAll(
                                resolveValues(
                                        clazz,
                                        keyValuePairTree.value(),
                                        argsMappingList,
                                        null,
                                        returnEnclosingParam,
                                        isResolvingType,
                                        detectionEngine,
                                        alreadyResolvedTrees));
                    }
                    // A DictionaryLiteralElement can be either a KeyValuePair or a
                    // UnpackingExpression -> handle the second case
                }
            }
            if (!keyResolved) {
                // If the list is empty or when there is no subscription index, or when the
                // subscription index does not correspond to an existing key, we resolve everything
                for (DictionaryLiteralElement dictionaryLiteralElement : listElements) {
                    if (dictionaryLiteralElement instanceof KeyValuePair keyValuePairTree) {
                        result.addAll(
                                resolveValues(
                                        clazz,
                                        keyValuePairTree.value(),
                                        argsMappingList,
                                        subscriptionIndex,
                                        returnEnclosingParam,
                                        isResolvingType,
                                        detectionEngine,
                                        alreadyResolvedTrees));
                    }
                }
            }
            return result;
        } else if (tree.is(Tree.Kind.SET_LITERAL)) {
            LinkedList<ResolvedValue<O, Tree>> result = new LinkedList<>();

            SetLiteral setLiteralTree = (SetLiteral) tree;
            List<Expression> listExpressions = setLiteralTree.elements();
            // In case of sets, there never is a subscription index: we resolve everything
            for (Expression expressionTree : listExpressions) {
                result.addAll(
                        resolveValues(
                                clazz,
                                expressionTree,
                                argsMappingList,
                                null,
                                returnEnclosingParam,
                                isResolvingType,
                                detectionEngine,
                                alreadyResolvedTrees));
            }
            return result;
        } else if (tree instanceof BinaryExpression binaryExpressionTree) {
            LinkedList<ResolvedValue<O, Tree>> result = new LinkedList<>();

            List<Expression> listExpressions =
                    Arrays.asList(
                            binaryExpressionTree.leftOperand(),
                            binaryExpressionTree.rightOperand());
            // In case of a binary expression, we resolve both sides
            for (Expression expressionTree : listExpressions) {
                result.addAll(
                        resolveValues(
                                clazz,
                                expressionTree,
                                argsMappingList,
                                null,
                                returnEnclosingParam,
                                isResolvingType,
                                detectionEngine,
                                alreadyResolvedTrees));
            }
            return result;
        } else {
            // When this case is reached, the Tree *must* be a value. If a non-value tree goes
            // through this case, it will *not* recursively resolve this tree.
            Optional<O> value = resolveConstant(clazz, tree);
            return value.map(t -> List.of(new ResolvedValue<>(t, (Tree) tree)))
                    .orElse(Collections.emptyList());
        }
    }

    /**
     * Resolve certain trees to a value they contain.
     *
     * @param tree - a Tree, that is expected to be a Name, a Literal or a None (if it is another
     *     type of tree, the function will return an empty result)
     * @return An optional value of class {@code clazz}, but in general a {@code String}, containing
     *     the resolved value if it exists
     */
    @Nonnull
    private static <O> Optional<O> resolveConstant(@Nonnull Class<O> clazz, @Nullable Tree tree) {
        if (tree == null) {
            return Optional.empty();
        }

        Object result = "";
        if (tree instanceof NumericLiteral numericLiteralTree) {
            String resultString = numericLiteralTree.valueAsString();
            try {
                result = Integer.parseInt(resultString);
            } catch (NumberFormatException e1) {
                try {
                    result = Double.parseDouble(resultString);
                } catch (NumberFormatException e2) {
                    LOGGER.debug(
                            "The detected NumericLiteral with value '{}' could not be converted to an Integer or a Double",
                            resultString);
                }
            }
        } else if (tree instanceof StringLiteral stringLiteralTree) {
            result = stringLiteralTree.trimmedQuotesValue();
        } else if (tree instanceof NoneExpression) {
            result = "None";
        } else if (tree instanceof Name nameTree) {
            result = nameTree.name();
        } else {
            // This case should never be reached
            LOGGER.debug(
                    "Detected tree type {} used in `resolveConstant` that is not currently supported",
                    tree.getKind());
        }

        try {
            return Optional.ofNullable(clazz.cast(result));
        } catch (ClassCastException exc) {
            return Optional.empty();
        }
    }

    /**
     * Returns the method definition tree of a function call
     *
     * @param tree - a Tree, that is expected to be a {@code Name}, {@code CallExpression} or {@code
     *     QualifiedExpression} representing a function call
     * @return A {@code FunctionDef} tree representing the method definition of the function call
     */
    private static FunctionDef getMethodDefinition(@Nonnull final Tree tree) {
        if (tree instanceof Name nameTree && nameTree.symbol() != null) {
            List<Usage> usages =
                    Optional.of(nameTree)
                            .map(Name::symbol)
                            .map(Symbol::usages)
                            .orElse(Collections.emptyList());
            for (Usage usage : usages) {
                if (usage.kind() == Usage.Kind.FUNC_DECLARATION
                        && usage.tree().parent() instanceof FunctionDef functionDefTree) {
                    return functionDefTree;
                }
            }
        } else if (tree instanceof CallExpression callExpressionTree) {
            return getMethodDefinition(callExpressionTree.callee());
        } else if (tree instanceof QualifiedExpression qualifiedExpressionTree) {
            return getMethodDefinition(qualifiedExpressionTree.name());
        }
        return null;
    }
}
