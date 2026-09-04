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
package com.ibm.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.plugin.bridge.ESLintResultParser;
import com.ibm.plugin.bridge.model.EslintCallExpression;
import com.ibm.plugin.bridge.model.EslintFileResult;
import com.ibm.plugin.javascript.api.BlockTree;
import com.ibm.plugin.javascript.api.CallExpressionTree;
import com.ibm.plugin.javascript.api.CallExpressionWithBlockTree;
import com.ibm.plugin.javascript.api.LiteralTree;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ESLintResultParserTest {

    @Test
    void toBlockTree_convertsCallWithAssignmentAndLiteralArgument() {
        EslintFileResult fileResult = new EslintFileResult();
        fileResult.bindings = Map.of("crypto", "crypto");
        EslintCallExpression call = new EslintCallExpression();
        call.kind = "call";
        call.methodName = "createHash";
        call.objectType = "crypto";
        call.resultType = "crypto.Hash";
        call.variableName = "hash";
        call.line = 2;
        call.column = 14;
        com.ibm.plugin.bridge.model.EslintArgument argument =
                new com.ibm.plugin.bridge.model.EslintArgument();
        argument.kind = "literal";
        argument.type = "string";
        argument.value = "sha256";
        argument.line = 2;
        argument.column = 36;
        call.arguments = List.of(argument);
        fileResult.calls = List.of(call);

        BlockTree blockTree = ESLintResultParser.toBlockTree(fileResult);

        assertThat(blockTree.statements()).hasSize(1);
        assertThat(blockTree.statements().get(0)).isInstanceOf(CallExpressionWithBlockTree.class);
        CallExpressionWithBlockTree wrapped =
                (CallExpressionWithBlockTree) blockTree.statements().get(0);
        CallExpressionTree callTree = wrapped.call();
        assertThat(callTree.methodName()).isEqualTo("createHash");
        assertThat(callTree.objectType()).isEqualTo("crypto");
        assertThat(callTree.resultType()).isEqualTo("crypto.Hash");
        assertThat(callTree.assignedSymbol().name()).isEqualTo("hash");
        assertThat(callTree.arguments()).hasSize(1);
        assertThat(callTree.arguments().get(0)).isInstanceOf(LiteralTree.class);
        assertThat(((LiteralTree) callTree.arguments().get(0)).value()).isEqualTo("sha256");
    }

    @Test
    void parseJson_readsRunnerOutput() throws Exception {
        String json =
                """
                {"files":[{"path":"/app/example.js","bindings":{"crypto":"crypto"},\
                "calls":[{"kind":"call","methodName":"createHash","objectType":"crypto",\
                "resultType":"crypto.Hash","variableName":null,"line":1,"column":0,"arguments":[]}]}]}
                """;

        var result = ESLintResultParser.parseJson(json);

        assertThat(result.files).hasSize(1);
        assertThat(result.files.get(0).calls).hasSize(1);
        assertThat(result.files.get(0).calls.get(0).methodName).isEqualTo("createHash");
    }
}
