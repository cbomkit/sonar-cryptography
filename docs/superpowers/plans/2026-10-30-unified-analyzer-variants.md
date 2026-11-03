# Plan: one branch, three build variants (plugin / plugin-with-go / library)

Date: 2026-10-30 · Status: **proposed, decisions recorded (§7), not started** · Target branch: `chore/analyzer-variants`

## 1. Goal

Combine `chore/downgrade-analyzers` and `chore/unbundle-sonar-analyzers` into one branch that
builds three artifacts from **one copy of the code**. No source file is duplicated, and no code
is switched off by commenting it out:

There is **one root `pom.xml`**. The variant is chosen with a Maven profile:

| Command                      | Profile                      | Artifact                                      | sonar-java / sonar-python                                 | Go                             | Licence of bundled analyzer code |
|------------------------------|------------------------------|-----------------------------------------------|-----------------------------------------------------------|--------------------------------|----------------------------------|
| `mvn clean package`          | `plugin` (active by default) | `sonar-cryptography-plugin-<v>.jar`           | `provided` (the server's own analyzers, `requirePlugins`) | no                             | none bundled                     |
| `mvn clean package -Pwith-go`| `with-go`                    | `sonar-cryptography-plugin-with-go-<v>.jar`   | `provided` (the server's own analyzers)                   | **bundled** (sonar-go, shaded) | **SSALv1** (sonar-go and the analyzer-commons classes it embeds) |
| `mvn clean package -Plib`    | `lib`                        | `sonar-cryptography-lib-<v>.jar`              | **bundled** LGPL 8.6.0.37351 / 4.23.0.17664 (shaded)      | no                             | LGPL-3.0, EPL-2.0 (jdt)          |

The `with-go` profile is meant for users who build a custom plugin themselves. It must warn
that the resulting JAR contains SSAL-licensed code that comes with use restrictions.

Meant to be published later to Maven and attached to releases: `sonar-cryptography-plugin` and
`sonar-cryptography-lib` (plus the parent and the shared modules they depend on), in one run:
`mvn deploy -Pplugin,lib`. `sonar-cryptography-plugin-with-go` is never published.
**For now nothing is published** (decided 2026-11-03): this plan only prepares and checks the
release run with a local dry run into a file repository (step 9).

**The library is for embedding in another tool**, not for installing in SonarQube (decision Q11).
The plan **creates it untested**: it is built, packaged and licence-checked, but its runtime
behaviour is not tested here. The user tests it himself. See §6 for what is and is not checked.

## 2. Starting point (verified 2026-10-30)

- `main` = `bee99643`.
- `chore/downgrade-analyzers` = `main` + **uncommitted** working tree (22 files): LGPL pins
  (java 8.6.0.37351, python 4.23.0.17664, analyzer-commons 2.14.0.3087), Go commented out
  (root pom module and dep, `engine/pom.xml` compiler exclude, `LanguageSupporter`,
  `CryptographyPlugin`, `ScannerManager`, plugin pom, `PluginTest` 10→8), `SSALv1.txt` replaced
  by `LGPL-3.0.txt`/`GPL-3.0.txt`/`EPL-2.0.txt`, rewritten `THIRD-PARTY-NOTICES.txt`, README
  licence section, regenerated `bom.json` files, LGPL/no-SSAL `verify_analyzer_packaging.py`,
  `CrossFileHookDetachTest` + `KeyGeneratorCaller.java` adapted to the 8.6 test kit (it only
  collects issues from the last file context). The plugin keeps the shade + legal-file and
  sources-JAR copying of `main`.
  The untracked noise (`.bob/`, `cpp/`, `javascript/`, `new/`, `scripts/`, `.scannerwork/`,
  `deps.slices.json`, `packages-and-licenses.txt`, `mapper/*iana*`, `mapper/count.py`, `*/bom/`)
  is **not** part of either variant and must not be committed.
- `chore/unbundle-sonar-analyzers` = 4 commits on `f4c834cb` (21 commits behind `main`):
  `9aee71b0` provided scope, `022f59c6` drop analyzer-commons/sonar-java helpers
  (`com.ibm.rules.RuleMetadataLoader`, `com.ibm.common.VisibleForTesting`, `JavaTreeUtils`),
  `df8b0460` public sonar-java API only (`JavaDetachedIssueQueue` + `JavaDetachedIssueSensor`),
  `941b680c` `Analyzers.JAVA/PYTHON` guards + `requirePlugins` with `sonar.{java,python}.minVersion`.
  It also comments Go out. Checkstyle `IllegalImport` (regexp) bans internal analyzer packages
  in main code.
- `git merge-tree main chore/unbundle-sonar-analyzers` conflicts only in `pom.xml` and
  `engine/.../detection/MethodMatcher.java`. Main has rewritten the Go sensor since (`58eea48b`).
- Go coupling outside the `go` module: only `engine/.../language/go/**` (5 files + `tree/`),
  and `LanguageSupporter.goLanguageSupporter()`, whose only caller is `go/.../GoAggregator`.
  The plugin module refers to Go in `CryptographyPlugin`, `ScannerManager` and `PluginTest`.
  No engine test refers to Go.
- analyzer-commons and Go (checked 2026-11-02 in `~/.m2`):
  - `sonar-go-plugin-1.32.0.5128.jar` **embeds its own copy** of 44 analyzer-commons classes,
    not relocated, under `org/sonarsource/analyzer/commons/{,annotations,collections,domain,internal/json/simple,xml}`.
    It has no Maven metadata for them, so their version is unknown, and its POM declares no
    analyzer-commons dependency. Its manifest says `Plugin-License: GNU LGPL 3`, but sonar-go 1.32
    is SSALv1 (see repo memory).
  - So the analyzer-commons version that `go/pom.xml` resolves does **not** decide which
    analyzer-commons classes reach the with-go JAR at runtime. It only matters for compiling our
    Go code and for its tests.
  - On `main`, `go/pom.xml` uses analyzer-commons only as `sonar-analyzer-test-commons` (test
    scope). Main code uses it once: `GoScannerRuleDefinition` imports
    `org.sonarsource.analyzer.commons.RuleMetadataLoader`, which step 1.3 replaces with
    `com.ibm.rules.RuleMetadataLoader`.
- Child modules declare `<parent>com.ibm:sonar-cryptography</parent>` with no `relativePath`,
  so Maven resolves the parent from `../pom.xml`.
- Licence gaps found on 2026-11-02 (both on `main` and on the downgrade branch):
  - `io.github.fynnth:cbomkit-csharp-parser:0.1.3` (declared in `engine/pom.xml`) is **EPL-2.0**.
    293 of its 294 classes are shaded into the plugin JAR, so it is in **all three** variants. No
    `THIRD-PARTY-NOTICES.txt` mentions it, and only the library has an `EPL-2.0.txt`. Its sources
    JAR is on Maven Central and its repository is https://github.com/fynnth/cbomkit-csharp-parser.
  - `com.google.googlejavaformat:google-java-format` is a `compile`-scope dependency in the root
    `<dependencies>`, so every module inherits it. No main or test code uses it; Spotless loads its
    own copy through `<googleJavaFormat><version>`. `minimizeJar` drops all its classes (0 in the
    JAR), but its transitive Guava 32.1.3-jre wins the nearest-first resolution over the Guava
    33.3.1-jre that python-frontend 4.23 asks for. So the 36 Guava classes in the JAR come from
    the wrong Guava version.

## 3. Key design decisions

### D1 — One root `pom.xml`; three profiles that only select modules
- The root `pom.xml` stays the parent and the aggregator. Its `<modules>` lists the shared modules
  every variant needs: `common`, `rules`, `mapper`, `enricher`, `output`, `engine`, `java`,
  `python`, `csharp`, `plugin-core` and `distribution` (the packaging parent, D3).
- Three profiles add the variant modules:

  ```xml
  <profiles>
    <profile>
      <id>plugin</id>
      <activation><activeByDefault>true</activeByDefault></activation>
      <modules><module>distribution/plugin</module></modules>
    </profile>
    <profile>
      <!-- WARNING: builds a JAR that contains SSALv1-licensed code (sonar-go and the analyzer-commons classes it embeds). -->
      <id>with-go</id>
      <modules><module>go</module><module>distribution/plugin-with-go</module></modules>
    </profile>
    <profile>
      <id>lib</id>
      <modules><module>distribution/library</module></modules>
    </profile>
  </profiles>
  ```

  - A bare `mvn` builds the default plugin. Naming any profile with `-P` switches the
    `activeByDefault` profile off, so `-Pwith-go` and `-Plib` build only their own variant.
  - Profiles can be combined. `-Pplugin,lib` builds the shared modules once and both variants
    meant for publication, which is what a later release would use (step 9.2: local dry run only).
- **Rule: a profile only adds `<modules>`.** It must not change versions, dependencies, scopes
  or plugin configuration that reach the shared modules. Otherwise the shared modules would be
  compiled differently per variant but published under the same coordinates. All variant
  differences live in the variant's **distribution module** (D3) and, for Go, in the `go` module.
  The shared modules are byte-for-byte the same in every variant.
- Variants that should not be combined: `plugin` and `with-go` both build a plugin with key
  `sonar-crypto-plugin`. Combining them works, but only one of the JARs can be installed. The
  README says so; no enforcer rule.
- Because `pom.xml` stays, IDE auto-import, dependabot and the existing `<parent>` declarations
  (no `relativePath`) keep working. IntelliJ lists the three profiles in the Maven tool window;
  enable `with-go` to see the `go` module. VS Code: setting `maven.profiles` or
  `java.configuration.maven.userSettings`; document it in CONTRIBUTING.md.

### D2 — One compile baseline for the analyzer API: the LGPL versions
`sonar.java.version=8.6.0.37351`, `sonar.python.version=4.23.0.17664` and
`sonar.analyzer-commons.version=2.14.0.3087` are used for every variant. The plugin variants
only use the *public* API, enforced by Checkstyle. That API is compatible with newer releases, so
compiling against an older API and running on the server's newer analyzer is safe.
`requirePlugins` keeps the runtime minimums: `sonar.java.minVersion=8.22.0.41895` and
`sonar.python.minVersion=5.14.2.29072` (SQ 26.1).
- Consequence: dependabot must ignore `sonar.java.version`, `sonar.python.version` and
  `org.sonarsource.analyzer-commons:*` (licence lock). Close the open dependabot branch for
  java 8.39.
- Safety net: a CI job (step 9) runs the shared modules' tests with
  `-Dsonar.java.version=8.22.0.41895 -Dsonar.python.version=5.29.0.35837
  -Dsonar.analyzer-commons.version=2.30.0.5193`. The test sources must then work with both test
  kits (see step 3.2).
- Alternative, only if D2 fails verification: the `lib` profile also sets the LGPL versions and the
  other profiles the newer ones. This breaks the D1 rule, because the shared modules would differ
  per variant under the same coordinates. It would then need separate versions or classifiers for
  the shared modules, and `-Pplugin,lib` could no longer be built in one run. Avoid it.

### D3 — Code module and distribution modules are separate
- The plugin code module keeps all plugin code and tests (`CryptographyPlugin`,
  `ScannerManager`, `Analyzers`, `OutputFileJob`, `Configuration`, …) and becomes
  `packaging jar`, with no shade and no sonar-packaging. Because the default distribution is
  published as `sonar-cryptography-plugin`, the code module must give up that artifactId:
  `git mv sonar-cryptography-plugin plugin-core`, artifactId `plugin-core` (in line with the
  other short module names `java`, `python`, `engine`, …).
- Artifact IDs = final names: `distribution/plugin` → `sonar-cryptography-plugin`,
  `distribution/plugin-with-go` → `sonar-cryptography-plugin-with-go`,
  `distribution/library` → `sonar-cryptography-lib`. All three keep plugin key
  `sonar-crypto-plugin`, so exactly one of them can be installed in a SonarQube instance at a time.
- New `distribution/pom.xml` (intermediate parent, inheriting from the root) holds the shared
  packaging configuration: sonar-packaging (key `sonar-crypto-plugin`, `pluginClass`, `jreMinVersion`,
  `sonarLintSupported`, `skipDependenciesPackaging`), shade (`minimizeJar`, signature-file filter,
  `ApacheNoticeResourceTransformer`, **`ServicesResourceTransformer`**), dependency-plugin unpack of
  legal files and sources JARs (driven by `${sonar.analyzer.groups}`), the `LICENSE.txt` resource and
  the `.SonarQube/plugins` copy. It reads its variant parameters from properties:
  `crypto.requiredForLanguages`, `crypto.requirePlugins`, `sonar.analyzer.groups`.
- **Legal files shared by all three variants (decision Q9)** live once, in
  `distribution/src/shared-resources/META-INF/third-party/`. `distribution/pom.xml` adds them as a
  resource directory (`${project.basedir}/../src/shared-resources`), so each child picks them up
  without a copy:
  - `EPL-2.0.txt`: needed in every variant, because the EPL-2.0 C# parser is in every JAR. It moves
    here from the library's resources, so the library no longer has its own copy.
  - `notices/cbomkit-csharp-parser.txt`: the notice section for the C# parser. Each variant's
    `THIRD-PARTY-NOTICES.txt` refers to it. It says the parser is made available under the EPL-2.0
    (see `META-INF/third-party/EPL-2.0.txt`), that the JAR contains it in object code form, and
    where its source is (EPL §3.2(b)): the Maven Central sources JAR for
    `${cbomkit.csharp.parser.version}` and https://github.com/fynnth/cbomkit-csharp-parser.
    The resource is filtered.
  - Its sources JAR is **not** bundled. No EPL source form is shipped for the parser, so §3.3(b)
    does not apply to it. The library still ships `EPL-2.0.txt` for the jdt sources (Q8), and the
    shared file covers that too.
  - The parser version moves into the root property `cbomkit.csharp.parser.version`, used by
    `engine/pom.xml` and the notice, so the two cannot drift.
- Three small children, each with only dependencies, properties and its own legal resources:
  - `distribution/plugin/`: depends on the plugin code, java, python and csharp; analyzers
    `provided`; `requirePlugins=java:${sonar.java.minVersion},python:${sonar.python.minVersion}`;
    languages `java,jsp,py,ipynb,cs`; `sonar.analyzer.groups` empty.
  - `distribution/plugin-with-go/`: as above plus the `go` module. Java and Python work exactly as in
    `distribution/plugin`: sonar-java and sonar-python stay `provided` (the server's built-in
    analyzers), with the same `requirePlugins=java:${sonar.java.minVersion},python:${sonar.python.minVersion}`
    and the same `Analyzers` guards. Only `sonar-go-plugin` is at `compile` scope and bundled; languages `java,jsp,py,ipynb,go,cs`; groups `org.sonarsource.go` only.
    sonar-go declares no analyzer-commons or sslr dependency; its analyzer-commons classes are
    embedded in its own JAR (§2), so no other SonarSource group is resolved. The build also adds
    the antrun download of the complete sonar-go
    release tree (from `main`); SSAL warning (D5).
  - `distribution/library/`: java/python at `compile` scope (bundled); no `requirePlugins`; languages
    `java,jsp,py,ipynb,cs`; groups `org.sonarsource.java,org.sonarsource.python,org.sonarsource.analyzer-commons,org.sonarsource.sslr`.
    **Shading keeps the bundled analyzers whole (finding F7).** Our code uses only the public
    analyzer API, so `minimizeJar` would drop nearly all sonar-java and sonar-python
    implementation classes (parser, semantic model, sensors), which an embedding tool needs to run
    an analysis. The library therefore adds shade `<filters>` with `<includes>**</includes>` for
    `org.sonarsource.java:*`, `org.sonarsource.python:*`, `org.sonarsource.analyzer-commons:*`,
    `org.sonarsource.sslr:*` and their transitive dependencies; a filter with an explicit include
    exempts an artifact from minimization. If that is not enough, set `minimizeJar=false` for the
    library only.
    **jdt-package (EPL-2.0), decision Q8:**
    - Its object code is in the JAR: shading copies in sonar-java's transitive dependency, about
      2,169 `org/eclipse/jdt/` classes.
    - Its sources JAR **is** bundled like those of the other analyzer modules (group
      `org.sonarsource.java`, about 8 MB).
    - Because the JAR distributes EPL code in source form, EPL §3.3(b) requires a copy of the
      licence. jdt-package does not bring one: its `about.html` only links to the EPL, and
      `about_files/LICENSE-2.0.txt` is the Apache licence. The shared `EPL-2.0.txt` (Q9) provides it,
      and `THIRD-PARTY-NOTICES.txt` refers to it (EPL §3.2 for the object code).
    - Its original legal files (`about.html`, `about_files/`) are also unpacked into
      `META-INF/third-party/analyzers/jdt-package-<version>-jar/`.
- Why three distribution modules rather than one module whose dependencies change per profile:
  the plugin and the library are both published, so they need different artifactIds, and a
  profile cannot change a module's artifactId. A single module would also violate the D1 rule.
  Each module still has its own small `pom.xml`, as every Maven module must. "One POM" refers to the
  root: there are no `pom-*.xml` variant files.
- Verify early (step 6.1) that sonar-packaging accepts a module whose `pluginClass` comes only from a
  shaded dependency. Fallback: `build-helper:add-source` of a single shared `src/plugin/java`
  directory in each distribution module (still one copy of the code).

### D4 — Language registration through a ServiceLoader SPI instead of hard-wired Go
- New interface `com.ibm.output.ILanguageModule` (in `output`, next to `IAggregator`):
  `String name()`, `boolean isAvailable()`, `List<Object> serverExtensions()` (rule definitions,
  always registered), `List<Object> scannerExtensions()` (registered only if `isAvailable()`),
  `List<INode> detectedNodes()`, `void reset()`.
- Implementations: `JavaLanguageModule` (available = `Analyzers`-style
  `Class.forName("org.sonar.plugins.java.api.CheckRegistrar")`, with extensions
  `JavaCheckRegistrar` and `JavaDetachedIssueSensor`), `PythonLanguageModule`, `GoLanguageModule`
  (`CryptoGoSensor`) and `CSharpLanguageModule` (always available). Each is registered in its own
  module's `META-INF/services/com.ibm.output.ILanguageModule`.
- A module class must not refer to the analyzer API in signatures or field types, only in method
  bodies after the `isAvailable()` check. `MissingAnalyzerTest` (hiding classloader) is the judge.
- `CryptographyPlugin` and `ScannerManager` iterate
  `ServiceLoader.load(ILanguageModule.class, CryptographyPlugin.class.getClassLoader())`. They no
  longer import language classes, so the Go JAR's presence alone decides Go support. The Java heap
  attribution (`ScannerManager.heapAttribution`) stays a Java-specific lookup, guarded by
  `Analyzers.JAVA`.
- `Analyzers` moves to `common` (or `output`) so that the language modules can use it.

### D5 — Go lives entirely in the `go` module and is SSAL-gated
- Move `engine/src/main/java/com/ibm/engine/language/go/**` to
  `go/src/main/java/com/ibm/engine/language/go/**` with `git mv` and unchanged package names.
  Remove `LanguageSupporter.goLanguageSupporter()`; `GoAggregator` creates `new GoLanguageSupport()`.
  Remove the `engine/pom.xml` compiler exclude.
- Remove `sonar-go-plugin` from the root `<dependencies>` (it is currently inherited by every module)
  and declare it only in `go/pom.xml`. Its version moves into the root `<dependencyManagement>`
  (it has no entry there today), so `go/pom.xml` declares it without a version.
- **analyzer-commons for Go: try 2.14.0.3087 first, switch to 2.30.0.5193 only if necessary.**
  `go/pom.xml` first uses the root's 2.14.0.3087 with no override. Only if step 4.4 shows that the
  Go module does not compile or its tests fail with 2.14 does `go/pom.xml` override
  `sonar.analyzer-commons.version` to 2.30.0.5193. The override is local to `go`, so the shared
  modules (D1 rule) and the library are unaffected. Either way, the with-go JAR contains the
  analyzer-commons classes that sonar-go embeds (§2), so the SSAL warning stays.
- Warnings for SSAL:
  1. An XML comment on the `with-go` profile in `pom.xml` and at the top of
     `distribution/plugin-with-go/pom.xml`.
  2. A build-time warning: an antrun `<echo level="warning">` in phase `validate` of
     `distribution/plugin-with-go`, printed at the start and repeated after `package`. It names
     sonar-go `${sonar.go.version}` and the analyzer-commons classes it embeds as SSALv1 (plus
     analyzer-commons 2.30 if step 4.4 needed the override), says the JAR is for private
     use under the SSAL terms only and must not be redistributed or offered as a service, and points
     to `META-INF/third-party/SSALv1.txt`.
  3. In the JAR: `SSALv1.txt` (restored from `main`) and a `THIRD-PARTY-NOTICES.txt` section for
     sonar-go.
  4. A README section, "Building the plugin with Go support".
  - Decided: the warning is enough. There is no opt-in property and no enforcer gate.
- The with-go variant is **never deployed or published**: `maven.deploy.skip=true` in
  `distribution/plugin-with-go` and in `go`, and it is excluded from `maven-publish.yml`.
- Runtime risk: SonarQube itself ships sonar-go, and every plugin exports
  `org/sonar/plugins/go/api/` to all others, siblings first. So the server's API classes would
  shadow the bundled ones. Mitigation: relocate `org.sonar.go`, `org.sonar.plugins.go` and
  `org.sonarsource.analyzer.commons` in this variant's shade. Verify with e2e on SQ 26.1 (step 10).

## 4. Target layout

```
pom.xml                          parent + aggregator; shared modules in <modules>;
                                 profiles plugin (default) / with-go / lib add the variant modules
distribution/pom.xml             shared packaging config (inherited by the three below)
distribution/src/shared-resources/META-INF/third-party/
                                 EPL-2.0.txt, notices/cbomkit-csharp-parser.txt (in every variant)
distribution/plugin/             artifact sonar-cryptography-plugin; …/META-INF/… (no bundled analyzers notice)
distribution/plugin-with-go/     artifact sonar-cryptography-plugin-with-go; …/SSALv1.txt, notices for sonar-go
distribution/library/            artifact sonar-cryptography-lib; …/LGPL-3.0.txt, GPL-3.0.txt, LGPL notices
plugin-core/                     plugin code + tests, packaging jar (renamed from sonar-cryptography-plugin/)
go/                              Go plugin code + Go engine code (moved from engine); only in profile with-go
```

## 5. Execution steps

Each step ends green (`mvn -o clean install`, and from step 6 on also `-Pwith-go` and `-Plib`) and is a separate
commit (`chore:`/`refactor:`/`feat:` subjects as in AGENTS.md). The user creates the commits himself,
with `git commit -s` (Signed-off-by).

### Step 0 — Preserve the inputs
- 0.1 Ask the user to commit the downgrade working tree on `chore/downgrade-analyzers`, without the
  untracked noise, or to make a stash or patch:
  `git diff > /tmp/downgrade.patch` plus copies of the 3 new licence texts.
- 0.2 Tag both inputs: `git tag wip/downgrade-input`, `git tag wip/unbundle-input 941b680c`.
- Progress (2026-11-02):
  - [x] Backup of the uncommitted downgrade changes: `/tmp/downgrade-backup/downgrade.patch`
        (22 files, `git apply --check -R` passes) plus `LGPL-3.0.txt`, `GPL-3.0.txt`, `EPL-2.0.txt`.
  - [x] `wip/unbundle-input` → `941b680c`.
  - [x] User committed the downgrade changes on `chore/downgrade-analyzers`: `ba60b03b` (25 files;
        identical to the backup patch plus the three licence texts; no untracked extras).
  - [x] `wip/downgrade-input` → `ba60b03b`.
  - Step 0 complete.

### Step 1 — Branch and port the unbundle work onto current `main`
- 1.1 `git switch -c chore/analyzer-variants main`.
- 1.2 `git cherry-pick 9aee71b0 022f59c6 df8b0460 941b680c`. Resolve `pom.xml` (keep main's newer
  properties and the unbundle `provided` scope, `minVersion` props and IllegalImport regexp) and
  `MethodMatcher.java` (main's rewrite plus the `VisibleForTesting` import). Make sure the new
  `JavaDetachedIssueSensor`, `RuleMetadataLoader` and other code compile against main's 21 newer
  commits (C# named parameters, rule-set registry, rewritten Go sensor).
- 1.3 Port the unbundle helpers to the **rewritten Go code** on main: no
  `org.sonarsource.analyzer.commons`, and use `com.ibm.rules.RuleMetadataLoader` and
  `com.ibm.common.VisibleForTesting`.
- 1.4 For now, keep Go as the unbundle branch leaves it (commented out). Gate:
  `mvn clean install` passes, including `MissingAnalyzerTest`, `PythonWithoutSonarJavaTest`,
  `JavaDetachedIssueSensorTest`, `RulesDefinitionTest`, `RuleMetadataLoaderTest`, and Checkstyle.
- Progress (2026-11-02):
  - [x] 1.1 `chore/analyzer-variants` created from `main` (`bee99643`).
  - [x] 1.2 The four commits applied with `git cherry-pick --no-commit` (the user commits). Conflicts:
        - `MethodMatcher.java`: kept `main`'s version. `main`'s rewrite no longer uses `SetUtils`,
          which was the only thing `022f59c6` changed there.
        - `pom.xml`: kept both `main`'s `sonar.go.source.*` properties (needed for with-go) and the
          new `sonar.{java,python}.minVersion` properties.
  - [x] 1.3 Nothing left to port: on `main`, `GoScannerRuleDefinition` and `GoInventoryRule` were the
        only Go users of the old helpers, and the cherry-pick updated both. The remaining
        `org.sonar.go.*` imports in `go/` are sonar-go internals, bundled by with-go later.
  - [x] 1.4 Gate: `mvn -o clean install` passes, with 512 tests (0 failures, 11 skipped), 0 Checkstyle
        violations and a clean `spotless:check`. The named tests pass: `MissingAnalyzerTest` 2,
        `PythonWithoutSonarJavaTest` 5, `JavaDetachedIssueSensorTest` 6, `RulesDefinitionTest` 3,
        `RuleMetadataLoaderTest` 5 and `CrossFileHookDetachTest` 1. Plugin JAR: `Plugin-RequirePlugins:
        java:8.22.0.41895,python:5.14.2.29072`, and 0 entries under `org/sonar/{java,python,go}/`
        or `org/sonarsource/`.
  - Known leftover (fixed in step 6): the plugin JAR still contains `SSALv1.txt` and the downloaded
    `sonar-go-…-source.zip`. The `main` antrun step and the legal resources still run although Go is
    disabled. Its `THIRD-PARTY-NOTICES.txt` is also still `main`'s: it says the JAR "contains portions
    of" sonar-java 8.22, sonar-python 5.29 and sonar-go 1.32, but it contains none of them. Do not
    publish JARs built before step 6.
  - [x] User committed step 1: `b435fd6a`. `mvn clean install` (online) on it: BUILD SUCCESS in 45 s,
        11 modules, 512 tests (0 failures, 0 errors, 11 skipped), 0 Checkstyle violations, and no
        tracked files changed by the build.

### Step 2 — SPI for language registration (D4)
- 2.1 Add `ILanguageModule` and the Java, Python and C# implementations with service files. Move
  `Analyzers`. `GoLanguageModule` is added in step 4, because the `go` module is not built yet.
- 2.2 Rewrite `CryptographyPlugin` and `ScannerManager` to use the SPI. Delete every
  `// Go temporarily disabled` / `// Go support temporarily disabled` comment.
- 2.3 Tests: `PluginTest` asserts the extension count per available module (no magic 8/10).
  `ScannerManagerTest` gets a fake module. `MissingAnalyzerTest` hides java and python in turn.
- Progress (2026-11-02):
  - [x] 2.1 `output/…/ILanguageModule` (`name`, `order`, `isAvailable`, `serverExtensions`,
        `scannerExtensions`, `detectedNodes`, `reset`). `JavaLanguageModule` (order 10),
        `PythonLanguageModule` (20) and `CSharpLanguageModule` (40, always available), each with
        `META-INF/services/com.ibm.output.ILanguageModule`. `Analyzers` moved with `git mv` to
        `common/…/com/ibm/common/Analyzers` (`isLoadable` public). Order 30 is left for Go.
  - [x] 2.2 `LanguageModules` (ServiceLoader on the plugin's class loader, sorted by `order`).
        `CryptographyPlugin` registers the server extensions of all modules and the scanner
        extensions of the available ones, and logs each skipped language. `ScannerManager`
        aggregates and resets the available modules only. `heapAttribution()` stays Java-specific,
        guarded by `Analyzers.JAVA`. The plugin's Java code has no Go comments left. Four remain,
        in `pom.xml` (module list), `engine/pom.xml`, `sonar-cryptography-plugin/pom.xml` and
        `LanguageSupporter`. They describe the build, where Go is still disabled, so step 4
        removes them.
  - [x] The plugin shade now has `ServicesResourceTransformer`. Without it the three service files
        collide and only one language would be registered. Plugin JAR: the service file lists
        Java, Python and C#, and `minimizeJar` keeps the three `*LanguageModule` classes,
        `LanguageModules`, `ILanguageModule` and `com/ibm/common/Analyzers`.
  - [x] 2.3 `PluginTest`: module names `[Java, Python, C#]`, and the extensions match what the
        modules declare plus `OutputFileJob` and the property definitions. `ScannerManagerTest`:
        a fake module; an unavailable module's `detectedNodes`/`reset` are never called. The
        `heapAttribution` tests are kept. `MissingAnalyzerTest`: unchanged, passes.
  - [x] Gate: `mvn -o clean install` BUILD SUCCESS, 516 tests (0 failures, 11 skipped), 0 Checkstyle
        violations. The first run failed with `ClassNotFoundException: PluginTest` while the class
        file existed. That was a race with VS Code's Java build writing to `target/`; the rerun
        passed.
  - [x] User committed step 2: `1101bb99` (14 files, signed off). Step 2 complete.

### Step 3 — Switch to the LGPL compile baseline (D2) and port the downgrade test fixes
This step comes before the Go move (F4), so the Go module is built against 2.14.0.3087 from the
start. Go is still disabled at this point, so the test fixes below only concern Java and Python.
- 3.1 Root properties: java 8.6.0.37351, python 4.23.0.17664, analyzer-commons 2.14.0.3087, with
  the downgrade's "last LGPL releases, licence review before upgrade" comment. Keep the `minVersion`
  properties.
- 3.2 Apply the downgrade `CrossFileHookDetachTest` and `KeyGeneratorCaller.java` changes, made
  **independent of the test kit**: filter the collected contexts per file and do not rely on
  `verifyNoIssues()` versus a `Noncompliant` marker. Then the test passes with both 8.6 and 8.22
  (D2 safety net).
- 3.3 Make the unbundle tests pass on 8.6/4.23 (`JavaDetachedIssueSensorTest`,
  `PythonWithoutSonarJavaTest`, `MissingAnalyzerTest`). Record every API gap in this file.
- 3.4 Dependabot (D2): add `ignore` entries for `org.sonarsource.java:*`, `org.sonarsource.python:*`
  and `org.sonarsource.analyzer-commons:*` to both maven entries in `.github/dependabot.yml`.
  Close the dependabot branch for java 8.39.
- 3.5 Gate: full test suite green on the baseline **and** with the 8.22/5.29/2.30 `-D` overrides.
- 3.6 Remove google-java-format from the build classpath (decision Q10):
  1. Delete the `google-java-format` `<dependency>` from the root `<dependencies>`. Keep the
     `google-java-format.version` property, which the Spotless `<googleJavaFormat>` configuration
     still uses.
  2. Check that nothing breaks: `mvn clean install` and `mvn spotless:check` pass, and
     `grep -rn "com.google.googlejavaformat" --include=*.java .` stays empty.
  3. Check the Guava version: `mvn -pl engine dependency:tree -Dincludes=com.google.guava:guava` now
     shows python-frontend's 33.3.1-jre (or whatever sonar-python 4.23 asks for), not 32.1.3-jre.
     If main code ever needs Guava directly, declare it explicitly in that module rather than
     relying on a transitive dependency.
  4. Compare the shaded JARs before and after (`unzip -Z1 | sort | diff`): no `com/ibm/` classes
     disappear, and the only differences are Guava and its annotation dependencies.
- Progress (2026-11-02):
  - [x] 3.1 Root `pom.xml`: java 8.6.0.37351, python 4.23.0.17664, analyzer-commons 2.14.0.3087,
        with the licence-review comment. The `minVersion` properties are unchanged.
  - [x] 3.2 On 8.6 only `CrossFileHookDetachTest` failed, as expected. Its fixture now carries a
        plain `// issue: (SecretKey) DES` comment instead of a `Noncompliant` marker. The test
        hands the rule a `java.lang.reflect.Proxy` of `JavaFileScannerContext` (public API only)
        that records `reportIssue*` calls instead of forwarding them. So the verifier sees no
        issues in either kit (`verifyNoIssues()`), and the test asserts exactly one direct issue:
        `KeyGeneratorCaller.java`, line 25, `(SecretKey) DES`. The detached-queue assertions stay.
        The test passes on 8.6 and on 8.22. The downgrade's version (filtering
        `JavaFileScannerContextForTests` contexts) was not used, because it needs test-kit
        internals and `verifyNoIssues()` would fail on 8.22.
  - [x] 3.3 No API gaps. `MissingAnalyzerTest` 2, `PythonWithoutSonarJavaTest` 5,
        `JavaDetachedIssueSensorTest` 6, `RulesDefinitionTest` 3 and `RuleMetadataLoaderTest` 5
        pass unchanged on 8.6/4.23/2.14.
  - [x] 3.4 `.github/dependabot.yml`: both maven entries ignore `org.sonarsource.java:*`,
        `org.sonarsource.python:*` and `org.sonarsource.analyzer-commons:*`. **Open, for the user:**
        close the stale dependabot PRs/branches on the remote. These are `sonar.java.version-*`
        8.10 … 8.41 (including 8.39.0.46279, also as a local branch) and
        `google-java-format-*` 1.24 … 1.36.1, which are obsolete after 3.6.
  - [x] 3.6 The google-java-format `<dependency>` is removed; the property stays for Spotless. No
        Java code uses it. Guava in `engine` is now python-frontend's 33.3.1-jre (`provided`),
        not 32.1.3-jre (`compile`).
        **Finding:** jsr305 (`javax.annotation.Nonnull`/`Nullable`, used by main code in every
        module) had only arrived through google-java-format → Guava. It is now declared directly
        in the root `<dependencies>` as `com.google.code.findbugs:jsr305:3.0.2` (`compile`,
        Apache-2.0), the same version as before.
        JAR diff: 0 `com/ibm/` entries lost; jsr305's `javax/annotation` is unchanged. Removed
        entries:
        - 32 Guava entries, all `package-info` or directories. `minimizeJar` had kept no real
          Guava class.
        - The Maven metadata of google-java-format, Guava and j2objc.
        - Guava's `proguard`/`native-image` files.
        - Two `META-INF/services` entries (`java.util.spi.ToolProvider`, `javax.tools.Tool`) that
          pointed at google-java-format classes the minimized JAR did not contain.
  - [x] 3.5 Gate (run in an rsync copy at `/tmp/sc-copy`, see below):
        - Baseline `mvn -o clean install`: BUILD SUCCESS, 516 tests (0 failures, 11 skipped),
          0 Checkstyle violations, `spotless:check` clean.
        - `mvn -o clean verify -Dsonar.java.version=8.22.0.41895 -Dsonar.python.version=5.29.0.35837
          -Dsonar.analyzer-commons.version=2.30.0.5193`: BUILD SUCCESS, 516 tests (0 failures,
          11 skipped).
  - Build note: in the repo itself, a full reactor build (`clean install`, or `-pl
    sonar-cryptography-plugin -am`) fails reproducibly with `ClassNotFoundException:
    com.ibm.plugin.PluginTest` while the class file exists. `-pl sonar-cryptography-plugin` alone
    passes. The identical sources pass in a copy that VS Code does not watch, so the cause is VS
    Code's Java server rebuilding the plugin project's `target/` folders while surefire starts, not
    the code. Run gates outside the IDE (or with the Java server stopped).
  - [x] User committed step 3: `4363654e` (4 files, signed off). Step 3 complete.

### Step 4 — Move Go into the `go` module (D5)
- 4.1 `git mv` the engine Go package. Drop `goLanguageSupporter()`, its commented imports and the
  engine compiler exclude. Add `GoLanguageModule` and its service file to the `go` module (D4).
- 4.2 Move the sonar-go dependency from the root `<dependencies>` to `go/pom.xml`. Do **not** add an
  analyzer-commons override yet (D5). Re-enable `<module>go</module>` in the root `<modules>` for now; step 5
  moves it into the `with-go` profile.
- 4.3 Gate: `mvn test -pl engine,go -am` passes. `grep -rn "language\.go\|org\.sonar\.go\|plugins\.go"
  engine/src` finds nothing.
- 4.4 analyzer-commons trial for Go (D5). The root already pins 2.14.0.3087 (step 3.1).
  1. `mvn -pl go -am clean test` with no override, so `go` resolves 2.14.0.3087.
     `mvn -pl go dependency:tree -Dincludes=org.sonarsource.analyzer-commons` shows only 2.14.
  2. If it passes, keep 2.14 and record "Go builds with analyzer-commons 2.14.0.3087" in this file.
  3. Only if it fails (compile error, `NoSuchMethodError`/`NoClassDefFoundError` in a test, or a
     test-kit API missing from `sonar-analyzer-test-commons` 2.14): first check whether the failure
     is in our code and can be fixed without a newer API. If not, add the override
     `<sonar.analyzer-commons.version>2.30.0.5193</sonar.analyzer-commons.version>` to
     `go/pom.xml` only, with a comment naming the failing class or method. Record the reason here.
  4. Also check for duplicate classes: the `go` test classpath contains both sonar-go's embedded
     analyzer-commons classes and the declared test-commons version. If tests fail only because of
     that mismatch, the 2.30 override is justified for that reason; record it.
  5. Gate: full test suite green, including `go`.
- Progress (2026-11-02):
  - [x] 4.1 The 10 files of `com.ibm.engine.language.go` moved with `git mv` to
        `go/src/main/java/com/ibm/engine/language/go/`; package names are unchanged.
        `LanguageSupporter` no longer has the commented `goLanguageSupporter()` or its imports.
        `GoAggregator` creates `new GoLanguageSupport()`. The `engine/pom.xml` compiler exclude is
        gone, and so is engine's whole `<build>` section, which held only that exclude.
        `GoLanguageModule` (order 30, always available, because the module is only packaged
        together with a bundled sonar-go) registers `GoScannerRuleDefinition` and `CryptoGoSensor`,
        as `main` did. Its service file is `go/src/main/resources/META-INF/services/…`.
  - [x] 4.2 `sonar-go-plugin` has a root `<dependencyManagement>` entry (`${sonar.go.version}`),
        and only `go/pom.xml` declares it (`compile`, no version, SSAL comment). The commented copy
        in the root `<dependencies>` is removed. `<module>go</module>` is re-enabled.
        `sonar-cryptography-plugin/pom.xml` replaces its commented go dependency with a note that
        the default plugin has no Go.
        No "temporarily disabled" comment is left in the repo.
  - [x] 4.3 `mvn -o clean install -pl engine,go -am`: BUILD SUCCESS, go 52 tests (0 failures,
        1 skipped), 0 Checkstyle violations. The skipped test is go's `CrossFileHookDetachTest`,
        which is `@Disabled` on `main` too. The grep for `language\.go|org\.sonar\.go|plugins\.go`
        in `engine/src` finds nothing.
  - [x] 4.4 **Go builds with analyzer-commons 2.14.0.3087; no override in `go/pom.xml`.**
        `dependency:tree -pl go -Dincludes=org.sonarsource.analyzer-commons` shows only 2.14:
        test-commons (`test`), and commons, regex-parsing, recognizers, xml-parsing and
        performance-measure (`provided`, through the root sonar-java dependency).
        Duplicate classes (4.4.4): sonar-go embeds 34 analyzer-commons classes (44 JAR entries,
        counting directories; §2 counts entries). 26 of them are also in commons 2.14, and 8 are
        not; test-commons has none. On go's classpath `sonar-go-plugin` comes before
        `sonar-analyzer-commons-2.14`, so sonar-go always uses its own copies. There is no
        mismatch, and no test failure that would justify 2.30.
  - [x] Fix found by the override run: four files in `go/…/language/go/tree/` used
        `org.checkerframework.checker.nullness.qual.NonNull`, which only arrived transitively
        (Guava → checker-qual: on `main` through google-java-format, now through python-frontend
        4.23's Guava). With 5.29 the build failed with "package … does not exist". They now use
        the codebase's `javax.annotation.Nonnull`; no `org.checkerframework` import is left.
  - [x] Gate (in `/tmp/sc-copy`):
        - Baseline `mvn -o clean install`: BUILD SUCCESS, 568 tests (0 failures, 12 skipped),
          0 Checkstyle violations.
        - With the 8.22/5.29/2.30 overrides (`clean verify`): BUILD SUCCESS, 568 tests.
        - `spotless:check` is clean.
        - Default plugin JAR: same file list as after step 3. Its service file still lists Java,
          Python and C#, and it has 0 Go entries.
  - [x] User committed step 4: `b7ae925f` (18 files, signed off). Step 4 complete.

### Step 5 — Profiles (D1)
- 5.1 `git mv sonar-cryptography-plugin plugin-core` and set artifactId `plugin-core`. Update the
  references (`docker-compose.yaml`, CI paths, docs, `verify_analyzer_packaging.py` path).
- 5.2 Root `<modules>`: the shared modules plus `distribution`. Add the profiles `plugin`
  (`activeByDefault`), `with-go` (`go`, `distribution/plugin-with-go`) and `lib`
  (`distribution/library`). Remove `go` from the root `<modules>`. Until step 6 creates the
  distribution modules, the profiles list only what exists.
- 5.3 Check the D1 rule: the profiles contain only `<id>`, `<activation>` (for `plugin`) and
  `<modules>`. `mvn help:effective-pom` of a shared module (for example `-pl java`) is identical
  with no profile, with `-Pwith-go` and with `-Plib`.
- 5.4 Check activation: `mvn help:active-profiles` shows `plugin` for a bare `mvn` and only
  `with-go` for `-Pwith-go`. Only the `with-go` reactor contains `go`.
- 5.5 Gate: `mvn clean install -DskipTests`, `mvn clean install -DskipTests -Pwith-go`,
  `mvn clean install -DskipTests -Plib` and `mvn clean install -DskipTests -Pplugin,lib` build the
  expected reactor (check the reactor summary).
- Progress (2026-11-02):
  - [x] 5.1 `git mv sonar-cryptography-plugin plugin-core`, artifactId `plugin-core`. The plugin
        key is set explicitly (`sonar-crypto-plugin`, manifest `Plugin-Key: crypto`), so the rename
        does not change it. Until step 6, `plugin-core` still builds the plugin JAR, so it has
        `<finalName>sonar-cryptography-plugin-${project.version}</finalName>`. That keeps the JAR
        name that the dev copy to `.SonarQube/plugins`, CI and the docs use. **Step 6 removes the
        `finalName`** together with the packaging configuration.
        References updated: root `<modules>`, `.github/workflows/maven.yml` (script and JAR path),
        `AGENTS.md`, `docs/LANGUAGE_SUPPORT.md` (module name and links),
        `docs/PERFORMANCE_TESTING.md` (paths), `verify_analyzer_packaging.py` (resource path) and
        `THIRD-PARTY-NOTICES.txt` (build file path). `docker-compose.yaml` has no module path.
        The remaining `sonar-cryptography-plugin` matches are the JAR name, the `bom.json` files
        (regenerated in step 8) and an older spec in `docs/superpowers/specs/`, left as is.
  - [x] 5.2 Root `<modules>`: common, rules, mapper, enricher, output, engine, java, python,
        csharp, plugin-core. `go` is no longer in it. Profiles: `plugin` (`activeByDefault`, no
        modules yet), `with-go` (`go`, with the SSAL warning comment) and `lib` (no modules yet).
        Comments name the distribution module each gets in step 6. `distribution` is not in
        `<modules>` yet, because it does not exist.
  - [x] 5.3 The profiles contain only `<id>`, `<activation>` (for `plugin`) and `<modules>`.
        `help:effective-pom` is byte-identical with no profile, `-Pwith-go`, `-Plib` and
        `-Pplugin,lib` for every shared module (common, rules, mapper, enricher, output, engine,
        java, python, csharp, plugin-core).
  - [x] 5.4 `help:active-profiles`: `plugin` for a bare `mvn`, only `with-go` for `-Pwith-go`,
        only `lib` for `-Plib`, and `lib` + `plugin` for `-Pplugin,lib`.
  - [x] 5.5 `clean install -DskipTests`, each in `/tmp/sc-copy`: the bare build, `-Plib` and
        `-Pplugin,lib` build the 10 shared modules plus the parent. `-Pwith-go` adds `go`. All
        BUILD SUCCESS.
  - [x] Tests:
        - Bare `clean install`: 516 tests (0 failures, 11 skipped). That is step 4's 568 minus
          go's 52.
        - `-Pwith-go`: 568 tests (12 skipped). With the 8.22/5.29/2.30 overrides as well: 568.
        - 0 Checkstyle violations. `spotless:check -Pwith-go` is clean.
        Plugin JAR `plugin-core/target/sonar-cryptography-plugin-2.0.0-SNAPSHOT.jar`: same
        manifest (`Plugin-Key: crypto`, `Plugin-RequirePlugins`, `Plugin-RequiredForLanguages`).
        Same entries as after step 4, except that `META-INF/maven/com.ibm/` now holds
        `plugin-core` instead of `sonar-cryptography-plugin`. It is still copied to
        `.SonarQube/plugins/`.
  - **Finding (pre-existing, for step 7):** the CI step "Verify analyzer redistribution materials"
    (`verify_analyzer_packaging.py`) fails. It expects the bundled analyzers' legal files, such as
    `META-INF/third-party/analyzers/sonar-java-plugin-8.6.0.37351-jar/about_files/LICENSE-2.0.txt`,
    which the plugin has not bundled since step 1. So CI is red on this branch from step 1 until
    step 7 replaces the script. It is not caused by the rename: the JAR content is unchanged
    apart from the Maven metadata.
  - [x] User committed step 5: `4fc7588a` (27 files, signed off). The first commit `898bdb61` held
        only the 22 staged renames; it was amended to include the 8 edited files (the root
        `pom.xml` and `plugin-core/pom.xml` plus six reference updates). Step 5 complete.

### Step 6 — Distribution modules (D3)
- 6.1 Spike: `distribution/plugin` with the code module shaded in. Check that sonar-packaging accepts
  it and that the manifest contains `Plugin-Class`, `Plugin-RequirePlugins`,
  `Plugin-RequiredForLanguages` and `Sonar-Version`. Check that `minimizeJar` keeps the
  `META-INF/services` implementations. If it does not, add shade `<filter>` includes for
  `com/ibm/plugin/*LanguageModule*`.
- 6.2 Move the packaging configuration out of `plugin-core/pom.xml` into
  `distribution/pom.xml`, and turn the code module into a jar. The distribution children are two
  levels below the root, so the two paths that today use `..` must change:
  - the `LICENSE.txt` resource: `${project.basedir}/..` becomes `${maven.multiModuleProjectDirectory}`;
  - the `.SonarQube/plugins` copy: `../.SonarQube/plugins` becomes
    `${maven.multiModuleProjectDirectory}/.SonarQube/plugins`.
  Set `createDependencyReducedPom` to `true` for the distribution modules, so the published POM of
  a shaded JAR does not list the dependencies it already contains (otherwise a consumer of
  `sonar-cryptography-lib` gets sonar-java and sonar-python twice).
- 6.3 Create `distribution/library` from the downgrade work tree: the LGPL and GPL texts
  (`LGPL-3.0.txt`, `GPL-3.0.txt`), `THIRD-PARTY-NOTICES.txt` (including its jdt-package section and
  the `EPL-2.0:` entry in "Licence texts"), `sonar.analyzer.groups`, no `requirePlugins`.
  `EPL-2.0.txt` comes from the shared resources (Q9). Keep `GPL-3.0.txt` (LGPL-3.0 §4(b)) and
  `EPL-2.0.txt` (EPL §3.3(b), because the jdt sources are bundled); neither is redundant (Q8).
  Add the shade `<filters>` that keep the bundled analyzers whole (D3, F7), and check V4b.
- 6.4 Create `distribution/plugin-with-go`: restore `SSALv1.txt` and main's sonar-go notice section and
  antrun source download; add the relocations, the warnings (D5) and deploy skip.
- 6.5 Create `distribution/plugin`: a notice that says no SonarSource analyzer is bundled and lists
  the required installed analyzers and their minimum versions.
- 6.6 Artifact IDs and final names (decided): `sonar-cryptography-plugin`,
  `sonar-cryptography-plugin-with-go`, `sonar-cryptography-lib`. All three share plugin key
  `sonar-crypto-plugin`, so only one can be installed at a time. Say so in the README.
  Plugin names in the manifest: `Sonar Crypto Plugin`, `Sonar Crypto Plugin (with Go)`,
  `Sonar Crypto Plugin (library)`.
- 6.7 C# parser notice (Q9):
  1. Add `distribution/src/shared-resources/META-INF/third-party/EPL-2.0.txt`: `git mv` it from
     the downgrade's plugin resources, so there is only one copy. Add
     `notices/cbomkit-csharp-parser.txt` there, and the shared resource directory to
     `distribution/pom.xml`.
  2. Add the root property `cbomkit.csharp.parser.version=0.1.3` and use it in `engine/pom.xml`.
  3. Each variant's `THIRD-PARTY-NOTICES.txt` gets a "Bundled in object code form" section that
     names the parser, refers to `notices/cbomkit-csharp-parser.txt`, and lists `EPL-2.0:` under
     "Licence texts". The plugin variant's notice is otherwise the "no SonarSource analyzer is
     bundled" notice from 6.5.
  4. Check the source link: `curl -sfI` on the Maven Central sources-JAR URL for the parser version
     returns 200.
  5. README licence section: mention the EPL-2.0 C# parser for all three variants.
- Progress (2026-11-03):
  - [x] 6.1 Spike. sonar-packaging does **not** accept a module whose plugin class comes only
        from a shaded dependency: it checks that `target/classes/com/ibm/plugin/CryptographyPlugin.class`
        exists ("Plugin class not found"). It has no parameter to point it elsewhere.
        Solution, simpler than the planned `build-helper` fallback: each variant unpacks the
        `plugin-core` JAR into its own `target/classes` (`dependency:unpack-dependencies`,
        execution `unpack-plugin-core`, phase `prepare-package`). sonar-packaging then finds the
        class. `minimizeJar` treats plugin-core's classes as the module's own classes and keeps
        them with everything they reference, as before, and the `ILanguageModule`
        implementations are kept as services. A shade filter excludes plugin-core's entries, so
        nothing is added twice. plugin-core still counts as shaded, so the dependency-reduced POM
        does not list it. No source is copied (V6).
        Manifest of `sonar-cryptography-plugin`: `Plugin-Class`, `Plugin-RequirePlugins:
        java:8.22.0.41895,python:5.14.2.29072`, `Plugin-RequiredForLanguages:
        java,jsp,py,ipynb,cs`, `Sonar-Version: 9.14.0.375`, `Plugin-Key: crypto`.
        The service file lists Java, Python and C#.
        Compared with the step 5 JAR, the class entries are identical. Changed entries:
        - `META-INF/maven/com.ibm/sonar-cryptography-plugin/` instead of `…/plugin-core/`.
        - Added `EPL-2.0.txt` and `notices/cbomkit-csharp-parser.txt`.
        - Removed `SSALv1.txt` and the sonar-go source ZIP (the step 1 leftover).
  - [x] 6.2 `plugin-core` is a plain `jar`. It keeps `plugin.properties` (read by `CBOMOutputFile`)
        and no other resource; the `finalName` from step 5 is gone. `distribution/pom.xml`
        (packaging `pom`, a shared module in the root `<modules>`) has, in `<pluginManagement>`:
        - the compiler, dependency, sonar-packaging, shade, resources and antrun configuration;
        - variant properties `crypto.pluginName`, `crypto.requiredForLanguages` and
          `sonar.analyzer.groups`;
        - the `sonar-jre-*` profiles.
        Resources: the variant's own `src/main/resources` and `resources-filtered`, the analyzer
        resources, the shared resources (`notices/` filtered) and `LICENSE.txt` from
        `${maven.multiModuleProjectDirectory}`. `createDependencyReducedPom=true`, written to
        `target/`.
        The deployed `sonar-cryptography-lib` POM lists only `sonar-plugin-api` (`provided`)
        besides test dependencies. sonar-java, sonar-python and plugin-core are not in it.
        Deviation: the `.SonarQube/plugins` copy is now an antrun execution, `copy-to-sonarqube`.
        Only `plugin` and `plugin-with-go` declare it, and it first deletes
        `sonar-cryptography-*.jar` there. The `maven-resources-plugin` execution ran in every
        variant, including the library. The three JARs share a plugin key, and SonarQube does not
        start with two plugins of the same key. Checked: the bare build leaves only the plugin JAR,
        `-Plib` leaves it unchanged, and `-Pwith-go` replaces it with the with-go JAR.
  - [x] 6.3 `distribution/library` (`sonar-cryptography-lib`, "Sonar Crypto Plugin (library)"):
        sonar-java and sonar-python at `compile` scope, no `requirePlugins`, the LGPL groups.
        `LGPL-3.0.txt`, `GPL-3.0.txt` and `THIRD-PARTY-NOTICES.txt` come from the downgrade
        commit `ba60b03b`. The notice now also has the C# parser section and the actual
        packaging (analyzers kept whole) and build file paths. Shade filters with
        `<includes>**</includes>` (`combine.children="append"`) cover the four SonarSource
        groups; `minimizeJar` is still on for the rest.
        - V4b: **100 %** for every bundled SonarSource artifact (19 JARs, for example
          sonar-java-plugin 8103/8103, jdt-package 3848/3848, python-frontend 588/588,
          sslr-core 183/183).
        - V4: no `Plugin-RequirePlugins`, 0 Go entries, Guava 33.3.1-jre. The 19 bundled sources
          JARs contain 0 "SSAL" matches. In the classes and resources, 2 files match: Unicode
          data files (`ucd/…`) containing "WASSALLAM". These are false positives; step 7's
          check must match "SSAL" as a word, not as a substring.
        - V4a: 2,232 `org/eclipse/jdt/` classes, `jdt-package-1.3.0.89-sources.jar`,
          `analyzers/jdt-package-1.3.0.89-jar/about.html`, `EPL-2.0.txt`.
        - JAR 63.1 MB; `Minimized 45075 -> 39385`.
        Note for step 7: the library JAR contains both `META-INF/LICENSE.txt` (ours) and
        `META-INF/license.txt` (from a dependency, also Apache). They differ only in case, which
        collides when unpacked on macOS and Windows.
  - [x] 6.4 `distribution/plugin-with-go` (`sonar-cryptography-plugin-with-go`, "Sonar Crypto
        Plugin (with Go)"):
        - Dependencies: plugin-core and `go`. Groups: `org.sonarsource.go`. Languages:
          `java,jsp,py,ipynb,go,cs`. `requirePlugins`: java and python, as in the plugin.
        - Legal files: `SSALv1.txt` moved here with `git mv`. `THIRD-PARTY-NOTICES.txt` started
          from `main`'s text, moved with `git mv`, and is rewritten: sonar-go section, Java and
          Python used from SonarQube, the C# parser, the relocations and the SSAL warning.
        - The antrun source download.
        - Relocations: `org.sonar.go`, `org.sonar.plugins.go` and
          `org.sonarsource.analyzer.commons` → `com.ibm.shaded.…`.
        - The SSAL warning (`<echo level="warning">`) in `validate`, and again in `package`
          after the shade and the copy. It is in the build log twice.
        - `maven.deploy.skip=true` here and in `go/pom.xml`.
        JAR (28.8 MB): 0 unrelocated `org/sonar/{java,python,go,plugins/go}` or
        `org/sonarsource` entries. 263 + 7 relocated sonar-go and analyzer-commons classes,
        11 `com/ibm/engine/language/go/` classes, the five native `sonar-go-to-slang-*`
        binaries, `SSALv1.txt`, the sonar-go sources JAR and source ZIP, and
        `analyzers/sonar-go-plugin-1.32.0.5128-jar/`. The service file lists Java, Python, C#
        and Go. `CryptoGoSensor` and `GoLanguageSupport` reference only `com/ibm/shaded/…`
        (0 unrelocated references).
        `SSALv1.txt` and sonar-go's own `licenses/LICENSE.txt` differ only in the named
        entity ("SonarSource SA" vs "SonarSource Sàrl"); the notice says so.
  - [x] 6.5 `distribution/plugin` notice: no SonarSource analyzer is bundled, the required
        installed analyzers and their minimum versions, no Go, and the C# parser.
  - [x] 6.6 Artifact IDs, final names and plugin names as decided. All three have
        `Plugin-Key: crypto`; the README says only one can be installed.
  - [x] 6.7 C# parser:
        1. `EPL-2.0.txt` comes from the downgrade commit into `distribution/src/shared-resources/`;
           it is the only copy in the tree (V17). `notices/cbomkit-csharp-parser.txt` names
           the version, the project and the sources JAR URL, and states EPL object-code
           distribution.
        2. Root property `cbomkit.csharp.parser.version=0.1.3`, used in `engine/pom.xml`.
        3. All three notices have the "Bundled in object code form" section and `EPL-2.0:`
           under "Licence texts". No unresolved `${…}` in any notice.
        4. `curl -sfI` returns 200 for the Maven Central sources JAR and for the GitHub project.
        5. README licence section rewritten: a table of the three variants, the C# parser
           (all variants), jdt-package (library), the shared plugin key and the SSAL warning
           for with-go.
  - [x] References: CI (`maven.yml`) and `docs/PERFORMANCE_TESTING.md` point at
        `distribution/plugin/target/`. `docs/LANGUAGE_SUPPORT.md` points at
        `crypto.requiredForLanguages`. The CI packaging check still fails until step 7.
  - [x] Gate (in `/tmp/sc-copy`), `mvn -o clean install`:
        - Bare: 516 tests (0 failures, 11 skipped); builds `distribution` and
          `sonar-cryptography-plugin`.
        - `-Pwith-go`: 568 tests (12 skipped); adds `go` and `sonar-cryptography-plugin-with-go`.
        - `-Plib`: 516 tests; adds `sonar-cryptography-lib`.
        - `-Pplugin,lib`: both.
        - All BUILD SUCCESS with 0 Checkstyle violations; `spotless:check -Pwith-go,lib` is clean.
  - [x] V15 (dry run, `mvn deploy -DaltDeploymentRepository=dry::file:///tmp/s6-repo`, online,
        because the deploy plugin refuses offline mode):
        - `-Pplugin,lib` deploys each of these exactly once: the parent, the 9 shared code
          modules, `plugin-core`, `distribution`, `sonar-cryptography-plugin` and
          `sonar-cryptography-lib`.
        - `-Pwith-go` deploys neither `go` nor `sonar-cryptography-plugin-with-go`: 2 "Skipping
          artifact deployment".
  - **Finding for step 8 (V16):** `mvn deploy` regenerates the committed `*/bom/bom.json` files.
    The root pom binds `cyclonedx:makeAggregateBom` to the `deploy` phase with
    `outputDirectory=${project.basedir}/bom/`. This is pre-existing (`main`), and `package`
    and `install` do not touch them. The dry run changed 9 of them in the copy, not in the repo.
    Step 8 must unbind it or move the output to `target/`.
  - Open for step 9: `maven-publish.yml` still runs a bare `mvn deploy`, which publishes the
    plugin but not the library, and CI (`maven.yml`) builds only the default variant.
  - [x] User committed step 6: `ab8cac6b` (21 files, signed off; nothing left unstaged). Git
        shows the rewritten with-go notice as a delete in `plugin-core` plus an add, and
        `SSALv1.txt` as a rename. Step 6 complete.

### Step 7 — Packaging verification script
- 7.1 Merge main's (Go-aware) and the downgrade's (LGPL/no-SSAL) `verify_analyzer_packaging.py` into
  one script with `--variant {plugin,plugin-with-go,library}`. Move it to `distribution/src/test/python/`.
  - `plugin`: no `org/sonar/java/`, `org/sonar/python/`, `org/sonar/go/`,
    `org/sonarsource/analyzer/commons/` entries. `Plugin-RequirePlugins` contains java and python.
    No `analyzer-sources/`. No "SSAL".
  - `plugin-with-go`: Go classes present (relocated), no java/python internals. `SSALv1.txt` and
    the sonar-go notice are present, and the sources ZIP and JAR are present. `go` is in
    `Plugin-RequiredForLanguages`.
  - `library`: today's downgrade checks (LGPL POM licences, legal files and sources per bundled
    module, no "SSAL" matched case-sensitively), no Go entries, no `Plugin-RequirePlugins`.
    jdt-package is checked like the other modules (sources JAR present, EPL via
    `OTHER_LICENCES`), and `LICENCE_TEXTS` stays `("LGPL-3.0.txt", "GPL-3.0.txt", "EPL-2.0.txt")`.
  - **All variants** (Q9, Q10):
    - `EPL-2.0.txt` and `notices/cbomkit-csharp-parser.txt` are present. The notice names the
      parser version that is actually bundled (read from its `META-INF/maven/.../pom.properties`,
      or from the build's dependency list) and contains the source URL.
    - Generic check: every bundled artifact whose POM licence is not Apache, MIT or BSD must be
      named in `THIRD-PARTY-NOTICES.txt`, and its licence text must be in
      `META-INF/third-party/`. The script gets the list of bundled artifacts from
      `dependency:list -DincludeScope=runtime`, written by the build into `target/`. This
      catches the next gap like the C# parser automatically.
    - No `com/google/googlejavaformat/` entries.
- Progress (2026-11-03):
  - [x] 7.1 Script moved with `git mv` from `plugin-core/src/test/python/` to
        `distribution/src/test/python/verify_analyzer_packaging.py` and rewritten around a
        `Checker` class: `check_common` for all variants, then `check_plugin`,
        `check_plugin_with_go` (Go source checks ported from main) or `check_library` (the
        downgrade checks, including the 100 % class counts per bundled module and jdt-package).
  - [x] `distribution/pom.xml`: new execution `list-bundled-dependencies` (`dependency:list`,
        `prepare-package`, `includeScope=runtime`, absolute file names) writes
        `target/bundled-dependencies.txt`. The script reads it by default from next to the JAR
        (`--dependencies` overrides) and only counts artifacts with at least one class in the JAR,
        so classes removed by `minimizeJar` do not count. Licences come from each POM and, if it
        declares none, its parents. The POM is parsed without relying on the XML namespace, since
        old POMs such as `xml-apis:1.4.01` have none.
  - [x] Additional checks for all variants: no duplicate entries, also case-insensitively;
        `META-INF/LICENSE.txt` equals the root `LICENSE.txt`; no unresolved `${` in the notices;
        manifest `Plugin-Key`/`Plugin-Class` and the language service entries match the variant.
  - Deviations:
    - The SSAL check matches the words `SSAL`/`SSALv1` and "source-available licence", not the
      substring `SSAL`, to avoid matches inside unrelated words in bundled files.
    - `PERMISSIVE` also accepts the SAX licence (public domain) and the W3C software licence,
      both from `xml-apis`.
  - [x] **Fix found by the case check (library):** sonar-java-plugin, spring-core, spring-jcl and
        spring-expression 6.1.13 each have `META-INF/license.txt`, which clashed with our
        `META-INF/LICENSE.txt` on case-insensitive file systems. All four copies are
        byte-identical (Apache-2.0 plus the Spring subcomponent licences: ASM, …). The library
        shade now excludes `META-INF/license.txt` for `*:*`; the same text stays in the JAR under
        `META-INF/third-party/analyzers/sonar-java-plugin-*-jar/META-INF/license.txt`. The
        `notice.txt` files are still merged into `META-INF/NOTICE` by the
        `ApacheNoticeResourceTransformer`.
  - [x] CI `maven.yml` runs `distribution/src/test/python/verify_analyzer_packaging.py --variant
        plugin distribution/plugin/target/sonar-cryptography-plugin-*.jar`.
  - [x] V2: all three variants pass. plugin: 21 bundled third-party artifacts, 1 not
        Apache/MIT/BSD (the C# parser). plugin-with-go: 23, 2 (adds sonar-go). library: passes,
        including 19 SonarSource artifacts bundled whole with their sources.
  - [x] Gates in `/tmp/sc-copy`: `mvn -o clean install` 516 tests, `-Pwith-go` 568, `-Plib` 516,
        all BUILD SUCCESS; `spotless:check` passes.
  - [x] User commits step 7 (`9b3d35a5`).

### Step 8 — Clean-up of variant leftovers
- 8.1 `grep -rn "temporarily disabled" --include=*.java --include=*.xml .` finds nothing.
- 8.2 No `<!--dependency` or `<!-- <module>` blocks remain in any POM.
- 8.3 The committed `bom.json` files describe the **default plugin variant** (decided). Today
  `makeAggregateBom` is bound to the `deploy` phase in the root `pom.xml`. A release run with
  `-Pplugin,lib` would then put the library's bundled analyzers into the aggregate BOM. So:
  - remove the `deploy` binding and keep only the plugin configuration in the root `pom.xml`;
  - generate the BOMs with a separate, explicit run that uses only the default profile:
    `mvn -Pplugin cyclonedx:makeAggregateBom` (needs a network connection);
  - `distribution/library` and `distribution/plugin-with-go` set `cyclonedx.skip=true`, so they
    never write a `bom/` folder, even when the goal is called with other profiles;
  - the `go` module has no committed `bom.json`.
- Progress (2026-11-03):
  - [x] 8.1 and 8.2: both scans find nothing (outside `target/`); no change needed.
  - [x] 8.3 Root `pom.xml`: `deploy` execution removed; the plugin configuration stays, with a
        comment naming the regeneration command. `distribution/library` and
        `distribution/plugin-with-go` set `cyclonedx.skip=true`. `go` (and with-go) are also left
        out by `skipNotDeployed` (default true, they set `maven.deploy.skip`).
  - Deviations:
    - The command is `mvn -Pplugin cyclonedx:makeBom cyclonedx:makeAggregateBom`, not only
      `makeAggregateBom`: that goal is an aggregator and, called from the command line, runs once
      and writes only the root BOM. The `deploy` binding used to run it in every module.
      `makeBom` writes the module BOMs.
    - `cyclonedx.skip` only stops a module's own run; the root aggregate still listed
      `sonar-cryptography-lib`. The root configuration therefore also sets
      `excludeArtifactId=sonar-cryptography-lib,sonar-cryptography-plugin-with-go,go`. Verified:
      with `-Pplugin,lib,with-go` no variant/go `bom/` folder is written and the root BOM has the
      same components as with `-Pplugin` (`sslr-core` stays, via the provided-scope analyzers).
  - [x] BOMs regenerated (`-Pplugin`): no `sonar-go` left. New: `csharp/`, `rules/`,
        `distribution/` and `distribution/plugin/` BOMs (the first two were never committed).
  - [x] Gates in `/tmp/sc-copy`: `mvn -o clean install` 516 tests, `-Pwith-go` 568, `-Plib` 516,
        all BUILD SUCCESS; all three variants pass `verify_analyzer_packaging.py`; no build writes
        a `bom/` folder; `spotless:check` and `checkstyle:check` pass.
  - [x] User commits step 8 (`396253ad`).

### Step 9 — CI, and publishing disabled (local dry run only)
**Nothing is published in this step, nor anywhere else in this plan.** No upload to GitHub
Packages, Maven Central or any other repository, no release, no release assets, no tags pushed,
and no workflow run that could deploy. Publishing is a separate, later decision by the user.
The only deploy that may run is the local dry run in 9.3, into a file repository under `/tmp`.

- 9.1 `maven.yml` (build and verify only):
  - A matrix over the profiles `plugin`, `with-go` and `lib`, running
    `mvn -B clean package -P${{ matrix.profile }}` and then the verification script with the
    matching `--variant`. Keep the "working tree clean" check in every matrix job.
  - One more job: `mvn -B test` with the 8.22/5.29/2.30 overrides.
  - No `actions/upload-artifact` of any JAR (no variant is downloadable from CI for now).
  - `permissions`: drop `packages: write`. Nothing in this workflow uploads packages.
    `contents: write` stays only because the dependency submission needs it.
  - The dependency submission runs in the `plugin` job only (as today, default variant); it
    uploads the dependency graph, not packages.
- 9.2 `maven-publish.yml` is disabled, so that it cannot publish, even when a release is created
  or someone starts it by hand:
  - Remove the `release: published` trigger; keep only `workflow_dispatch`.
  - `permissions: contents: read` only (no `packages: write`), so a deploy to GitHub Packages
    would be refused even if one ran.
  - Replace the deploy step with a step that prints "Publishing is disabled until the variant
    release is approved; see docs/superpowers/plans/2026-10-30-unified-analyzer-variants.md
    step 9" and exits 1. No `mvn deploy` in the file.
  - Keep the intended release command as a comment only, for the later decision:
    `mvn --batch-mode deploy -Pplugin,lib` (would publish the parent `sonar-cryptography`, the
    shared modules, `plugin-core`, `distribution` (pom), `sonar-cryptography-plugin` and
    `sonar-cryptography-lib`; release assets would be the plugin and the lib JAR).
  - Leave `<distributionManagement>` in the root `pom.xml` unchanged; it is harmless without a
    deploy run and needed later.
- 9.3 Local dry run (the only deploy allowed). Run it in `/tmp/sc-copy`, never in the repo:
  - Always pass a file repository: `mvn -B deploy -Pplugin,lib
    -DaltDeploymentRepository=dry::file:///tmp/s9-deploy-dry-run`. Never run `mvn deploy` without
    `-DaltDeploymentRepository=...file://...`: the default target is GitHub Packages.
    In the log, confirm that every upload went to the file URL
    (`grep -c 'Uploading to dry: file:///tmp/s9-deploy-dry-run'` > 0 and
    `grep -c 'maven.pkg.github.com'` = 0).
  - Online is needed only because the deploy plugin refuses `-o`; it only resolves dependencies.
  - Check (V15): the parent, the 9 shared modules, `plugin-core`, `distribution`,
    `sonar-cryptography-plugin` and `sonar-cryptography-lib` each appear exactly once under
    `/tmp/s9-deploy-dry-run`; `-Pwith-go` (same file repository) adds nothing for `go` or
    `sonar-cryptography-plugin-with-go` ("Skipping artifact deployment").
  - Check (V16): no committed `bom.json` changes in the copy.
  - Delete `/tmp/s9-deploy-dry-run` afterwards.
- 9.4 `docker-compose.yaml` and the `.SonarQube/plugins` copy (local only): only the last-built
  variant ends up there. Each distribution module deletes the other variants' JARs first.
- 9.5 Grep after the step: `grep -rn "mvn.*deploy" .github/` finds only the comment in
  `maven-publish.yml`; `grep -rn "packages: write\|release:" .github/workflows/` finds nothing.
- Progress (2026-11-03). **Nothing was published.**
  - [x] 9.1 `maven.yml`: job `build` is a matrix (`plugin`/`plugin`, `with-go`/`plugin-with-go`,
        `lib`/`library`, `fail-fast: false`): package, verify script, clean-tree check. The
        dependency submission runs only in the `plugin` job. New job `test-newer-analyzers`
        (`mvn -B test` with 8.22.0.41895 / 5.29.0.35837 / 2.30.0.5193). `permissions:
        contents: write` only; no artifact upload.
  - [x] 9.2 `maven-publish.yml`: only `workflow_dispatch`, `permissions: contents: read`, one
        step that prints the notice and exits 1. The release command is a comment only. Both
        workflows parse as YAML.
  - [x] 9.3 Dry run in `/tmp/sc-copy` (script `/tmp/s9-checks.sh`). Extra guard beyond the plan:
        in the copy, the `<distributionManagement>` URL was rewritten to a local `file://` path
        and Maven ran with a settings file without servers, so no upload could reach GitHub
        even if `altDeploymentRepository` were ignored.
        - `-Pplugin,lib`: 54 uploads, all to `dry: file:///tmp/s9-deploy-dry-run`; 0 other
          uploads; 0 `maven.pkg.github.com`. Deployed once each: `sonar-cryptography`, the 9
          shared modules, `plugin-core`, `distribution`, `sonar-cryptography-plugin`,
          `sonar-cryptography-lib` (V15).
        - `-Pwith-go`: 2 "Skipping artifact deployment"; no `go` or
          `sonar-cryptography-plugin-with-go` in the repository (V15). It does redeploy the
          shared modules, as a separate run would.
        - No committed `bom.json` changed in the copy (V16). Dry-run repository deleted.
  - [x] 9.4 Already done in step 6 (`copy-to-sonarqube` deletes the other variants' JARs; the
        library does not copy). No change.
  - [x] 9.5 Greps: only the comment in `maven-publish.yml` matches `mvn.*deploy`; no
        `packages: write` and no `release:` in `.github/workflows/`.
  - [x] CI equivalent run locally in `/tmp/sc-copy`: `package -Pplugin` 516 tests, `-Pwith-go`
        568, `-Plib` 516, each variant passes the verify script; override `test` 516; all
        BUILD SUCCESS.
  - [x] User commits step 9 (`c1c1778e`).

### Step 10 — Documentation
- README: build section (`mvn clean package`, `-Pwith-go`, `-Plib`; do not combine `plugin` and
  `with-go`), version compatibility per variant, the "Using" section
  (the plugin variant needs the server's Java/Python analyzers; rule repositories per variant), a
  licence section per variant, and a with-go SSAL warning box.
- AGENTS.md and CONTRIBUTING.md: the existing commands (`mvn test`, `mvn test -pl java`,
  `mvn spotless:apply`) keep working for the default variant. Add `-Pwith-go` for Go work
  (`mvn test -pl go -Pwith-go`) and `-Plib` for the library, and explain how to enable the
  profiles in IntelliJ and VS Code (D1).
- README licence section: one licence paragraph per variant (the pointer to the
  `sonar.java.version` comment in `pom.xml` stays).
- `docs/LANGUAGE_SUPPORT.md`: a new language registers an `ILanguageModule` service instead of
  editing `CryptographyPlugin` and `ScannerManager`.
- Update repo memory `/memories/repo/sonar-java-unbundling.md` (Go is no longer "disabled").
- Progress (2026-11-03):
  - [x] README: version compatibility (2.0.0 per variant; 1.x rows bounded at 1.7.0),
        installation (2.0.0 unreleased, build it; required analyzers; one variant only), Go
        footnote, rule repositories and rules per variant (`sonar-cs-crypto` added), a build
        section with the profile table, the `plugin`+`with-go` rule, the `.SonarQube/plugins`
        copy, `mvn test -pl go -am -Pwith-go` and the verify script, a new section "Building the
        plugin with Go support" with the SSAL warning box, and a licence section with one
        paragraph per variant (the `sonar.java.version` pointer is back, in the library
        paragraph).
  - [x] AGENTS.md: module list with `distribution/`, a "Build Variants" paragraph (profiles,
        SSAL, publishing disabled, public API only, LGPL compile versions) and the variant,
        Go-test and verify commands.
  - [x] CONTRIBUTING.md: build section per variant (JAR now in `distribution/plugin/target`)
        and "Profiles in the IDE". F5 resolved: vscode-java has
        `java.configuration.maven.userSettings` but no profile setting (`maven.profiles` does
        not exist), so the guide uses a settings file with `<activeProfiles>`. Verified: with
        such a file Maven activates only `with-go` (the default `plugin` turns off) and the
        reactor contains `go` and `sonar-cryptography-plugin-with-go`.
  - [x] `docs/LANGUAGE_SUPPORT.md`: registration through `ILanguageModule` and the service file
        (replaces the `CryptographyPlugin`/`ScannerManager` edits), packaging the module into a
        variant, analyzer dependency in `provided` scope with the licence note, current
        `crypto.requiredForLanguages`, diagram (Go engine code in `go`), fixed `GoScanContext`
        link.
  - [x] `docs/TROUBLESHOOTING.md`: building copies one variant to `.SonarQube/plugins`.
  - [x] Repo memory updated.
  - Deviation: the plugin key is `crypto` (manifest `Plugin-Key`), not `sonar-crypto-plugin`
    as Q1 says; the README said `sonar-crypto-plugin` since step 6 and now says `crypto`.
  - Checks: no broken relative links in README, CONTRIBUTING, AGENTS and `docs/*.md`; the
    documented `mvn test -pl go -am -Pwith-go` (52 go tests) and `mvn test -pl java` pass in
    `/tmp/sc-copy`. V13 holds.
  - Still open in §6: V11 (e2e on SQ 26.1 with the plugin and the with-go JAR) has not been run
    on this branch; it needs the local SonarQube and a user token.
  - [x] User commits step 10 (`e8e2096d`).

## 6. Validation checklist (run after each relevant step; all must hold at the end)

- [x] V1 `mvn clean package`, `mvn clean package -Plib` and `mvn clean package -Pwith-go` all
      succeed with tests, Checkstyle and Spotless.
- [x] V2 Each JAR passes `verify_analyzer_packaging.py --variant <v>`.
- [x] V3 `unzip -l` of the plugin JAR: 0 entries under `org/sonar/java/`, `org/sonar/python/`,
      `org/sonar/go/` or `org/sonarsource/`; the manifest has
      `Plugin-RequirePlugins: java:8.22.0.41895,python:5.14.2.29072`.
- [x] V4 `sonar-cryptography-lib` JAR: bundled sonar-java 8.6.0.37351, sonar-python 4.23.0.17664, commons 2.14.0.3087,
      sslr 1.24; 0 "SSAL" matches; no Go classes; no `Plugin-RequirePlugins`.
- [x] V4b `sonar-cryptography-lib` JAR keeps the bundled analyzers whole (F7): for every bundled
      `org.sonarsource.{java,python,analyzer-commons,sslr}` artifact, all of its classes are in the
      JAR (same per-artifact count as in the audit of 2026-11-02, but expecting 100 %).
- [x] V4a `sonar-cryptography-lib` JAR and jdt-package: `org/eclipse/jdt/` classes,
      `analyzer-sources/jdt-package-*-sources.jar`, `META-INF/third-party/EPL-2.0.txt` and
      `analyzers/jdt-package-*-jar/about.html` are present; `THIRD-PARTY-NOTICES.txt` lists
      jdt-package as EPL-2.0 and refers to `EPL-2.0.txt`.
- [x] V5 With-go JAR: contains Go engine and plugin classes and the relocated sonar-go; `SSALv1.txt`
      present; the build log contains the SSAL warning; `go` is in `Plugin-RequiredForLanguages`;
      `mvn deploy` skips it.
- [x] V5a `go` resolves analyzer-commons 2.14.0.3087 (`dependency:tree`), unless step 4.4 recorded a
      reason for the 2.30 override. Any override is in `go/pom.xml` only, with a comment.
- [x] V6 No duplicated source: `git ls-files '*.java' | xargs -n1 basename | sort | uniq -d`
      shows no new duplicates compared with `main`, and there is no copy of a Java file under
      `distribution/`.
- [x] V7 No commented-out variant code (step 8.1/8.2 greps are empty).
- [x] V8 `engine` has no Go references; `pom.xml` has no `sonar-go-plugin` in `<dependencies>`.
- [x] V8a There is exactly one root POM (`ls pom*.xml` = `pom.xml`). Its profiles contain only
      `<id>`, `<activation>` and `<modules>`, and the effective POM of every shared module is the
      same with no profile, `-Pwith-go` and `-Plib` (step 5.3).
- [x] V9 The shared modules' tests pass on the LGPL baseline and with the 8.22/5.29/2.30 overrides.
- [ ] V10 `MissingAnalyzerTest`: a Java-only, a Python-only and a C#-only classpath each load the
      plugin without `NoClassDefFoundError` (plugin variant).
- [ ] V11 e2e on SQ 26.1 (docker compose, fixture `/tmp/crypto-e2e`, user token):
      - plugin JAR: the server starts; scans of Java-only, Python-only and mixed projects produce
        `cbom.json` with the expected assets; cross-file Java issues appear.
      - with-go JAR: Go assets appear in the CBOM, and nothing clashes with the server's bundled
        sonar-go (no `LinkageError` or "Unable to load components").
      - library JAR: **not tested** (Q11). The user tests it in the embedding tool.
- [ ] V12 ~~The CBOM of the plugin and the library variant are identical~~ Dropped (Q11): no
      runtime test of the library.
- [x] V13 README, AGENTS.md and CONTRIBUTING.md name the three profiles and the command for each;
      the README has the SSAL warning for with-go.
- [x] V14 Final JAR names: `sonar-cryptography-plugin-<v>.jar`,
      `sonar-cryptography-plugin-with-go-<v>.jar`, `sonar-cryptography-lib-<v>.jar`.
- [x] V15 A dry run of `mvn deploy -Pplugin,lib` publishes the parent, the shared modules,
      `plugin-core`, `distribution`, `sonar-cryptography-plugin` and `sonar-cryptography-lib`
      exactly once each. A dry run of `mvn deploy -Pwith-go` publishes nothing for `go` or
      `sonar-cryptography-plugin-with-go`.
- [x] V16 The committed `bom.json` files are unchanged after `mvn deploy -Pplugin,lib` (dry run),
      `mvn package -Plib` and `mvn package -Pwith-go` (git diff is empty). Only
      `mvn -Pplugin cyclonedx:makeAggregateBom` changes them.
- [x] V17 All three JARs contain `META-INF/third-party/EPL-2.0.txt` and
      `META-INF/third-party/notices/cbomkit-csharp-parser.txt`. The notice names the bundled parser
      version, and its source URL returns 200. There is exactly one `EPL-2.0.txt` in the source tree
      (`git ls-files '*EPL-2.0.txt'`).
- [x] V18 `google-java-format` is not a dependency of any module (`mvn dependency:tree
      -Dincludes=com.google.googlejavaformat` is empty with every profile). `mvn spotless:check` still
      works. The Guava in the library JAR is the version python-frontend 4.23 asks for.

### Final pass (2026-11-03, committed HEAD `e8e2096d`)

Run on a `git archive HEAD` export in `/tmp/sc-final` (scripts `/tmp/s6-final.sh`,
`/tmp/s6-final-2.sh`, summary `/tmp/s6f-summary.txt`). **Nothing was published**: the only deploy
was the dry run into a temporary file repository, with the GitHub Packages URL rewritten in the
copy and a settings file without servers; the repository was deleted afterwards.

- V1: `clean install` with `-Pplugin` 516 tests, `-Pwith-go` 568, `-Plib` 516; 0 failures, 0
  errors; 0 Checkstyle violations; `spotless:check` passes with each profile. The two javac
  warnings in `engine` (`SyntaxToken.line()`/`column()` deprecated for removal) are not
  Checkstyle findings.
- V2: all three JARs pass `verify_analyzer_packaging.py`. V14: the three final names as listed.
- V3: 0 entries under `org/sonar/java/`, `org/sonar/python/`, `org/sonar/go/`,
  `org/sonarsource/`; `Plugin-RequirePlugins: java:8.22.0.41895,python:5.14.2.29072`.
- V4/V4a/V4b: sources of sonar-java 8.6.0.37351, sonar-python 4.23.0.17664, analyzer-commons
  2.14.0.3087, sslr-core 1.24.0.633 and jdt-package 1.3.0.89 (19 sources JARs); 0 `SSAL`/`SSALv1`
  words in the JAR and all nested archives; 0 Go entries; no `Plugin-RequirePlugins`; 2,232
  `org/eclipse/jdt/` classes, `EPL-2.0.txt`, jdt `about.html` and sources JAR present, jdt-package
  in the notice; all 19 bundled SonarSource artifacts have all their classes (script asserts
  kept == total).
- V5: 9 `com/ibm/engine/language/go/` classes, 45 Go plugin classes, 270 relocated
  `com/ibm/shaded/` classes, 0 unrelocated sonar-go/analyzer-commons entries, `SSALv1.txt`,
  `go` in `Plugin-RequiredForLanguages`, the SSAL warning twice in the build log, and 2
  "Skipping artifact deployment" in the dry run.
- V5a: `go` resolves analyzer-commons 2.14.0.3087 only; no override in `go/pom.xml`.
- V6: 17 duplicate Java basenames in HEAD and on `main`, none new; no Java file under
  `distribution/`. V7: both greps empty.
- V8: no Go dependency or import in `engine/` (the one match is a Javadoc sentence in
  `CSharpScanContext` that mentions Go); no `sonar-go-plugin` in the root `<dependencies>`.
- V8a: one root `pom.xml`; profiles contain only `id`, `activation` (plugin) and `modules`; the
  effective POM of the 11 shared modules is byte-identical with no profile, `-Pwith-go` and
  `-Plib`.
- V9: with the 8.22/5.29/2.30 overrides, `-Pplugin` 516 and `-Pwith-go` 568 tests pass.
- V10: see the open item below.
- V13: README, AGENTS.md and CONTRIBUTING.md name the three profiles and their commands; the
  README has the SSAL warning.
- V15: `-Pplugin,lib` uploaded 54 files, all to the file repository (0 other uploads, 0
  `maven.pkg.github.com`): `sonar-cryptography`, the 9 shared modules, `plugin-core`,
  `distribution`, `sonar-cryptography-plugin` and `sonar-cryptography-lib` once each. `-Pwith-go`
  added nothing for `go` or `sonar-cryptography-plugin-with-go`.
- V16: the source tree, including every `bom.json`, is unchanged after the three builds and
  after the dry runs.
- V17: all three JARs have `EPL-2.0.txt` and the parser notice; the notice names 0.1.3, which
  is the bundled version (`bundled-dependencies.txt`); the project URL and the Maven Central
  sources JAR URL return 200; one `EPL-2.0.txt` in the tree.
- V18: no `google-java-format` in `dependency:tree` with any profile; Guava in the library is
  33.3.1-jre (`pom.properties` in the JAR), the version sonar-python 4.23's POM declares.

Still open:
- **V10, partly.** The committed `MissingAnalyzerTest` has two cases, without sonar-java
  (Python and C#) and without sonar-python (Java and C#). The C#-only case (both hidden) is not
  in it. Added in the copy only, it passes (3 of 3). To meet V10 as written, add that case to the
  committed test.
- **V11.** Not run: SonarQube is not running and the fixture `/tmp/crypto-e2e` no longer exists.
  Needs `docker compose up`, a fixture and a user token.
- V12: dropped (Q11).

## 7. Decisions (2026-10-30)

| #  | Question | Decision | Where applied |
|----|----------|----------|---------------|
| Q1 | Artifact and final names | `sonar-cryptography-plugin` (default), `sonar-cryptography-plugin-with-go`, `sonar-cryptography-lib`. The plugin key stays `sonar-crypto-plugin` for all three (not asked to change). The code module is renamed `plugin-core` to free the artifactId. | §1, D3, §4, 6.6, V14 |
| Q2 | SSAL gate for with-go | A warning is enough; no opt-in property. | D5 |
| Q3 | Variant described by the committed `bom.json` | The default plugin variant. | 8.3, V16 |
| Q4 | Parent POM name | ~~Rename to `pom-parent.xml`~~, superseded by Q6. | — |
| Q5 | Publish the library | Yes: Maven and release asset, **but not yet** (2026-11-03): nothing is published until the user decides; only a local dry run. | §1, 9.2, V15 |
| Q6 | Three `pom-*.xml` files or profiles | One root `pom.xml` with the profiles `plugin` (default), `with-go` and `lib`. The profiles only select modules. | §1, D1, §4, step 5, 9.1, 9.2, V1, V8a |
| Q7 | analyzer-commons version for Go | Try 2.14.0.3087 first; switch `go` to 2.30.0.5193 only if necessary. | §2, D5, 4.2, 4.4, V5a |
| Q8 | jdt-package (EPL-2.0) in the library | Bundle its object code and its sources JAR like the other analyzer modules, and include `EPL-2.0.txt` (EPL §3.3(b)). `GPL-3.0.txt` stays, because LGPL-3.0 §4(b) requires a copy of the GPL. (Linking the jdt source instead of bundling it was considered and rejected.) | §1, D3, §4, 6.3, 7.1, V4a |
| Q9 | EPL-2.0 C# parser in all variants | Add a notice section with an EPL statement and source links, and `EPL-2.0.txt`, to all three JARs. Both files live once, in the shared distribution resources. The parser's sources are not bundled. | §2, D3, §4, 6.3, 6.7, 7.1, V17 |
| Q10 | google-java-format on the compile classpath | Remove the dependency; Spotless keeps its own copy. | §2, 3.6, 7.1, V18 |
| Q11 | Purpose and testing of the library | It is for embedding in another tool. Build it untested: only the build, packaging and licence checks (V1, V2, V4, V4a, V4b, V14, V15, V17, V18) apply to it. No e2e scan, no CBOM comparison, no consumer test; the user tests it himself. | §1, V11, V12, §8, F1 |

No open questions remain in this table; see the open findings in §9.

## 8. Risks

| Risk | Mitigation |
|------|------------|
| The unbundle tests or code need an API newer than 8.6/4.23 | Step 3.3 finds it early; fallback is the D2 profile alternative |
| The test kits differ (8.6 collects only the last file's issues) | Test-kit-independent assertions (3.2) and the CI override job |
| sonar-packaging rejects a code-less distribution module | Spike 6.1; fallback is a shared `add-source` directory |
| `minimizeJar` drops SPI implementations | Shade filter includes; checked in V2 |
| The server's sonar-go API shadows the bundled Go classes | Shade relocation in with-go; V11 |
| A profile changes something in a shared module, so a published shared module depends on the variant | D1 rule; effective-POM comparison in step 5.3 and V8a |
| `-Pplugin,with-go` builds two plugin JARs with the same key | README note; with-go is never deployed |
| A release run with `-Pplugin,lib` puts the library's dependencies into the committed BOM | Separate `cyclonedx:makeAggregateBom` run with `-Pplugin` only; `cyclonedx.skip` in lib/with-go (8.3, V16) |
| A contributor forgets `-Pwith-go` and the Go code is not compiled or tested | CI matrix builds all three profiles; CONTRIBUTING.md |
| Go tests pass with analyzer-commons 2.14 but the embedded sonar-go copy differs at runtime | Runtime uses only sonar-go's embedded classes (relocated with it); e2e in V11 |
| The library's bundled sonar-java 8.6 / sonar-python 4.23 internals do not work in the embedding tool | Not tested here (Q11); the user tests it |

## 9. Validation (2026-11-02)

The plan was checked against the repository. Facts confirmed: `main` = `bee99643`; the unbundle
branch has the 4 listed commits on `f4c834cb`; the root `pom.xml` module list and the commented
`go` module; the 22 uncommitted downgrade changes (not yet committed, so step 0 is still open).
The decisions table (Q1–Q11) matches the sections it points to.

Second pass (2026-11-02, after Q11): step 0 is still open (22 uncommitted changes, no `wip/*`
tags yet). Fixed:
- D3: the with-go variant listed analyzer-commons/sslr groups that "sonar-go pulls in". sonar-go
  declares neither (§2), so its group list is `org.sonarsource.go` only.
- D5: sonar-go has no `<dependencyManagement>` entry in the root today; the plan said its version
  "stays" there. It now moves there.
- F7 (new, below): `minimizeJar` would strip the library.

Fixed in this pass:
- Step 2.1 listed four SPI implementations, but `GoLanguageModule` cannot compile before step 3
  enables the `go` module. It moved to the Go step (now 4.1).
- Step 6.2: the distribution children are two levels deep. The inherited `LICENSE.txt` resource
  (`${project.basedir}/..`) and the `../.SonarQube/plugins` copy would point into `distribution/`.
  Both now use `${maven.multiModuleProjectDirectory}`.
- Step 6.2: `createDependencyReducedPom` is `false` today. A published shaded JAR would then still
  declare the dependencies it contains. It is set to `true` for the distribution modules.

Open findings (to be resolved during execution):
- **F1 — What is the library for?** Resolved (Q11): it is for embedding in another tool, and it is
  built untested; the user tests it himself. Two consequences for the build, both unchanged by
  Q11:
  - The library stays a SonarQube plugin JAR (sonar-packaging, plugin key `sonar-crypto-plugin`).
    The `Plugin-*` manifest entries are kept for the time being (user decision 2026-11-02); they are
    harmless when the JAR is used as a plain library. Revisit after the user has tested the library.
  - With `createDependencyReducedPom=true`, the published POM of `sonar-cryptography-lib` no
    longer lists what the JAR contains. `sonar-plugin-api` stays `provided`, so the embedding
    tool must put `sonar-plugin-api` on its own classpath.
- **F2 — Shade relocation in with-go (D5).** Relocating `org.sonar.go`, `org.sonar.plugins.go` and
  `org.sonarsource.analyzer.commons` rewrites class references, but not strings. sonar-go's
  non-class resources live under `org/sonar/l10n/go/` (73 rule files plus 3 for external
  linters), which is outside the relocated packages, so rule metadata keeps working. Check in
  step 6.4 that nothing loads a class or resource by a string name inside the relocated packages
  (`grep` the sonar-go classes for `"org.sonar.go` and `"org/sonar/go`).
- **F3 — The library's sonar-java/sonar-python scope.** The root `<dependencies>`
  declares both analyzers `provided` for every module, including `distribution/library`. The library
  must redeclare them at `compile` scope to override that. A redeclaration in a child POM wins, but
  step 6.3 must check it with `mvn -pl distribution/library dependency:tree`.
- **F4 — Step order.** Resolved: the LGPL baseline step (now step 3) comes before the Go move
  (now step 4), so the Go analyzer-commons trial (4.4) runs against 2.14.0.3087 directly.
- **F5 — VS Code profile setting (D1).** `maven.profiles` and `java.configuration.maven.userSettings`
  are not verified. Check the current vscode-java documentation before writing CONTRIBUTING.md.
- **F6 — `activeByDefault`.** Maven turns `plugin` off whenever another profile *of the root POM*
  is activated, also by a property or file activation. The root must therefore have no other
  auto-activated profile. Today it has none; the `sonar-jre-defined` profile is in the plugin POM
  and is unaffected. Keep it that way, and check it in step 5.4.
- **F7 — `minimizeJar` and the library.** The shade configuration uses `minimizeJar=true`, which
  keeps only classes reachable from our code. On the downgrade branch our code still used sonar-java
  internals, so 5,261 of 8,105 sonar-java-plugin classes survived. On the unified branch our code
  uses only the public API, so far fewer would survive, and the library would lack the analyzer
  implementation an embedding tool needs. Resolved in D3 by exempting the bundled analyzers from
  minimization; checked by V4b. This is a packaging check only and does not test the library (Q11).
  The plugin variants keep `minimizeJar=true` unchanged.
