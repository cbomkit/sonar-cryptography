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
package com.ibm.plugin.rules.resolve;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.detection.Finding;
import com.ibm.engine.utils.DetectionStoreLogger;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.sonar.plugins.python.api.PythonCheck;
import org.sonar.plugins.python.api.PythonVisitorContext;
import org.sonar.plugins.python.api.symbols.Symbol;
import org.sonar.plugins.python.api.tree.Tree;
import org.sonar.python.checks.utils.PythonCheckVerifier;

/**
 * Cross-file guard for the shared call-stack bucketing optimization.
 *
 * <p>The AST-detach branch narrowed {@code CallStackAgent.onNewHookSubscription} from scanning
 * every recorded-call bucket to fetching only the single bucket keyed by the hooked method name's
 * hash (see {@code bucketsToScan}). That narrowing is shared by all languages, so it must hold that
 * a call recorded while analyzing one file is still found by a hook created while analyzing another
 * file in the same scan — Python detaches nothing ({@code notifyLeaveFile} is a no-op here), so the
 * whole-scan call stack is exactly where cross-file resolution lives.
 *
 * <p>This is the Python analogue of {@code CrossFileHookDetachTest} (Java): {@code
 * make_private_key(...)} is defined in {@code imports/CrossFileHookWrapper.py} and called from
 * {@code CrossFileHookResolveTestFile.py}; the {@code SECP384R1} literal must resolve across the
 * file boundary via the hook on the wrapper's parameter.
 *
 * <p><b>Empirical status (branch {@code feat/callstack-ast-detach}):</b> {@code @Disabled} because
 * Python does not currently perform scan-level cross-file symbol resolution — the call {@code
 * make_private_key} in the caller module does not link to its {@code def} in the wrapper module, so
 * no detection is recorded and nothing is raised (same limitation as the {@code @Disabled} {@code
 * ResolveImportedStructTest}). The bucketing narrowing is therefore <em>not</em> a risk for Python:
 * it is only ever exercised within a single file, and the within-file wrapper-hook path (identical
 * minus the file boundary, e.g. {@code fun7}/{@code fun8} in {@code
 * ResolveValuesWithHooksTestFile.py}) still passes on this branch — proving the record-time key
 * ({@code getKeyFormT}) stays aligned with the matcher-lookup key. This test stands as a forward
 * guard: if Python ever gains cross-file resolution, remove {@code @Disabled} and it must pass,
 * catching any bucketing regression that would silently drop cross-file detections.
 */
class CrossFileHookResolveTest extends TestBase {

    public CrossFileHookResolveTest() {
        super(ResolveValuesWithHooks.rules());
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> detectionStore,
            @Nonnull List<INode> nodes) {
        // Verification is driven by the Noncompliant marker in the caller fixture.
    }

    @Disabled("cross-file symbol resolution not supported in Python — see class Javadoc")
    @Test
    void crossFileHookResolvesAcrossTwoModules() {
        PythonCheckVerifier.verify(
                List.of(
                        "src/test/files/rules/resolve/CrossFileHookResolveTestFile.py",
                        "src/test/files/rules/resolve/imports/CrossFileHookWrapper.py"),
                this);
    }

    @Override
    public void update(@Nonnull Finding<PythonCheck, Tree, Symbol, PythonVisitorContext> finding) {
        final DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> detectionStore =
                finding.detectionStore();
        (new DetectionStoreLogger<PythonCheck, Tree, Symbol, PythonVisitorContext>())
                .print(detectionStore);
        detectionStore
                .getDetectionValues()
                .forEach(
                        iValue ->
                                detectionStore
                                        .getScanContext()
                                        .reportIssue(
                                                this, iValue.getLocation(), iValue.asString()));
    }
}
