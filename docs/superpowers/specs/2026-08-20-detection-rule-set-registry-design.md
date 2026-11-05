# Detection rule sets as a registry (memoization built in)

**Issue:** [#478](https://github.com/cbomkit/sonar-cryptography/issues/478)
**Branch:** `refactor/detection-rule-set-registry` (off `main`)
**Date:** 2026-08-20

## Problem

Issue #476 fixed a rule-graph blow-up: `JavaDetectionRules.rules()` expanded
into ~521,000 distinct rule objects and could exhaust the SonarScanner Engine
heap. PR #477 fixed it by memoizing every no-arg `rules()` accessor, bringing
the count to 2,563.

The fix works, but it is opt-in boilerplate repeated in every rule class:

```java
private static final Supplier<List<IDetectionRule<Tree>>> RULES = Memoize.of(() -> buildRules(null));
@Nonnull public static List<IDetectionRule<Tree>> rules() { return RULES.get(); }
```

Because `rules()` is static, the type system cannot enforce the memo. A new
rule class can forget it and reintroduce the blow-up. Three modules ship a
reflective CI test (`RuleMemoizationEnforcementTest`) as a stopgap; the newer
`csharp` module has neither the helper nor the test.

**This change does not reduce heap.** #477 already did that. This is about the
shape of the code: remove the wrapper, and make memoization the only possible
behaviour.

### Where the cost actually is

Of the 122 Java classes that use `DetectionRuleBuilder`, 97 already hold their
rules in `static final` fields — those were never the problem (JCA and friends
were ~126 objects of the 521,000). The cost lives in the 23 that build rules
inside a method, in a loop, and embed a shared subtree per iteration (2 classes
match neither pattern):

```java
for (String macClass : constructorBlockCipher) {
    constructorsList.add(new DetectionRuleBuilder<Tree>()
        ...
        .addDependingDetectionRules(BcBlockCipher.all())      // rebuilt every iteration
        .withDependingDetectionRules(BcMacInit.rules()));     // rebuilt every iteration
}
```

The bug is therefore *"an embed site rebuilt a subtree"*. The design below
removes the ability to rebuild at an embed site.

## Approaches considered

| Approach | Wrapper gone | Unbypassable | Call sites moved | Verdict |
|---|---|---|---|---|
| Keep `Memoize`, add it to `csharp` | no | no | 0 | Rejected — leaves the boilerplate |
| `static final List` field per class | yes | no | 0 | Rejected — see below |
| Abstract base + `INSTANCE` field (#478 as written) | yes | yes | ~570 | Rejected — adds ceremony at every call site |
| **Registry + abstract base** | **yes** | **yes** | **~570** | **Chosen** |
| Dedupe inside `DetectionRuleBuilder.build()` | yes | yes | 0 | Impossible — see below |

**Why not a `static final List` field.** For the 97 simple classes the change is
cosmetic. For the 23 that matter it makes field declaration order load-bearing
(`BcBlockCipherEngine` reads `enginesEmptyConstructors` while building) and
makes reading any unrelated static member — `BcBlockCipher.blockCiphers` is
public and read elsewhere — build the whole subtree. New fragility exactly where
the risk is, for a cosmetic gain elsewhere.

**Why builder-level dedupe is impossible.** `DetectionRule` is a record, but one
of its components is `MethodMatcher`, a normal class holding `Predicate`
lambdas. Lambdas have no value equality, so a structural cache either matches
nothing or wrongly merges rules that differ only in their factory.

## Design

### Bases (new, in `engine`, package `com.ibm.engine.rule`)

```java
public abstract class DetectionRuleSet<T> {
    protected DetectionRuleSet() {}
    protected abstract List<IDetectionRule<T>> buildRules();
}

public abstract class ContextualDetectionRuleSet<T> extends DetectionRuleSet<T> {
    protected abstract List<IDetectionRule<T>> buildRules(@Nonnull List<IDetectionContext> contexts);

    @Override
    protected final List<IDetectionRule<T>> buildRules() {
        return buildRules(List.of());
    }
}
```

184 rule classes extend `DetectionRuleSet`; 9 extend `ContextualDetectionRuleSet`
(the 8 that take a context today, plus the new `BcBlockCipherAndEngines`).

`buildRules` is `protected`, so nothing outside `com.ibm.engine.rule` can call
it. An interface would force it `public`, and `new BcDigests().buildRules()`
would still build a fresh subtree. `protected` makes the registry the only door.

`engine` is already a dependency of `java`, `python`, `go` and `csharp`, and
`IDetectionRule<T>` is unbounded, so one generic base serves all four modules.

### Registry (new, same package)

```java
public final class RuleSets {
    private RuleSets() {}

    public static <T> List<IDetectionRule<T>> rulesOf(Class<? extends DetectionRuleSet<T>> type);

    public static <T> List<IDetectionRule<T>> rulesOf(
            Class<? extends ContextualDetectionRuleSet<T>> type, IDetectionContext... contexts);
}
```

Two caches:

- **No-arg path** — a `ClassValue<List<IDetectionRule<?>>>`. Instantiates the
  class via `getDeclaredConstructor().newInstance()`, calls the `protected`
  `buildRules()` (same package), stores `List.copyOf(...)`.
- **Contextual path** — a `ConcurrentHashMap` keyed by
  `record CacheKey(Class<?> type, List<IDetectionContext> contexts)`.

**Both caches must be recursion-safe.** Builds are recursive:
`BcMac.buildRules()` calls `rulesOf(BcDigests.class)`, and
`BcOAEPEncoding.buildRules(ctxs)` calls
`rulesOf(BcAsymCipherEngine.class, engineCtx)`. `ClassValue` supports this by
design. The contextual map must use `get` → build → `putIfAbsent` and **never
`computeIfAbsent`**, which throws `IllegalStateException` on a nested update
(Java 9+). Both may build a duplicate under a race and discard it; identity is
stable once installed. Rule construction happens once at scanner start, so the
race is theoretical.

Null contexts stay in the key positionally, so `rules(null, engineCtx)` keeps
working. The key list must therefore permit nulls (`Arrays.asList`, not
`List.of`).

Overload resolution: `rulesOf(BcDigests.class)` picks the non-varargs method
(phase 1 beats varargs), so it hits the `ClassValue` fast path and resolves to
the default context through `buildRules(List.of())`.

### A rule class

```java
public final class BcDigests extends ContextualDetectionRuleSet<Tree> {
    @Override
    protected List<IDetectionRule<Tree>> buildRules(@Nonnull List<IDetectionContext> contexts) {
        IDetectionContext context = contexts.isEmpty() || contexts.get(0) == null
                ? new DigestContext()
                : contexts.get(0);
        ...
    }
}
```

Gone from every rule class: the `Memoize` import, the `Supplier` field, the
public accessor, the private constructor. **No rule class keeps any public
accessor**, contextual ones included.

### Call sites

```java
// before
.addDependingDetectionRules(BcDigests.rules())
.addDependingDetectionRules(BcDigests.rules(new DigestContext(Map.of("kind", "MGF1"))))

// after (static import of RuleSets.rulesOf)
.addDependingDetectionRules(rulesOf(BcDigests.class))
.addDependingDetectionRules(rulesOf(BcDigests.class, new DigestContext(Map.of("kind", "MGF1"))))
```

### `equals`/`hashCode` on detection contexts

The contextual cache needs value equality. No context is currently compared
with `==` or used as a hash key anywhere in the codebase, so adding it is safe.
There are 13 concrete context classes and the state is not all in one place:

| Class | State to compare |
|---|---|
| `DetectionContext` (base) | `getClass()` + `properties` |
| `KeyContext`, `SignatureContext` | plus their `kind` field |
| `PrivateKeyContext`, `PublicKeyContext`, `SecretKeyContext` | inherit `KeyContext`; `getClass()` separates them |
| `ProtocolContext` | implements the interface directly — `getClass()` + `kind` |
| `PRNGContext` | no state — `getClass()` only |
| `AlgorithmParameterContext`, `CipherContext`, `DigestContext`, `KeyAgreementContext`, `KeyDerivationFunctionContext`, `MacContext` | inherit the base, nothing extra |

Compare on `getClass()`, not `instanceof` — that is what keeps
`PublicKeyContext` and `PrivateKeyContext` distinct. `DetectionContext` will
also take `Map.copyOf(properties)` in its constructor so a caller cannot mutate
a map a cache key depends on.

Indirect effect, checked: `DetectionRule` is a record holding a context, so its
`equals` changes meaning. Nothing in main code puts rules in a `HashSet` or
`HashMap`, and `RuleGraphMemoizationTest` dedups with an `IdentityHashMap`. No
behaviour depends on it.

### Two structural exceptions

**`BcBlockCipher.all()`** — the registry gives one list per class, so a class
cannot hold two. `all()` is `rules()` plus `BcBlockCipherEngine.rules()` and has
26 call sites. It moves to its own class, which also takes over the single
`all(ctx)` site:

```java
public final class BcBlockCipherAndEngines extends ContextualDetectionRuleSet<Tree> {
    @Override
    protected List<IDetectionRule<Tree>> buildRules(@Nonnull List<IDetectionContext> contexts) {
        IDetectionContext[] ctx = contexts.toArray(new IDetectionContext[0]);
        return Stream.of(rulesOf(BcBlockCipher.class, ctx).stream(),
                         rulesOf(BcBlockCipherEngine.class, ctx).stream())
                .flatMap(i -> i).toList();
    }
}
```

**The four aggregators** (`JavaDetectionRules`, `PythonDetectionRules`,
`GoDetectionRules`, `CSharpDetectionRules`) become `DetectionRuleSet`
subclasses like any other. That moves 11 call sites outside the detection
package: four `*InventoryRule` classes, four `TestBase` classes, two export
tests, and `RuleGraphMemoizationTest`.

### Out of scope

`JavaReorganizerRules.rules()` and its siblings return `List<IReorganizerRule>`,
a different type with a different job. Not touched.

## Blast radius

| Module | Rule classes | Call sites (main) | Call sites (test) |
|---|---:|---:|---:|
| `java` | 135 + 1 new (`BcBlockCipherAndEngines`) | 434 | 9 |
| `python` | 22 | 24 | 9 |
| `go` | 23 | 44 | 34 |
| `csharp` | 12 | 16 | 1 |
| **Total** | **193** | **518** | **53** |

`engine` gains 3 new classes and 5 edited context classes (`DetectionContext`,
`KeyContext`, `SignatureContext`, `ProtocolContext`, `PRNGContext`). No other module has
`.rules(` call sites.

No reference cycles exist in any module (java 138 classes / 239 edges,
python 18 / 18, go 25 / 34, csharp 13 / 12), so recursive lazy building
terminates.

## Testing

- Replace the three `RuleMemoizationEnforcementTest` copies with one stronger
  check, present in **all four** modules: *no class under
  `com.ibm.plugin.rules.detection` declares a public static method returning a
  rule list*. After this refactor there is no legitimate reason for one, so the
  check is exact rather than heuristic. Forgetting the base class becomes a
  build failure.
- New `RuleSetsTest` in `engine`: same identity across calls; same identity for
  equal contexts; different identity for different contexts; a recursive build
  (a set whose `buildRules` calls `rulesOf` for another set) neither deadlocks
  nor throws.
- New context equality tests: `PublicKeyContext` vs `PrivateKeyContext`,
  `KeyContext` instances differing only by `kind`, `DetectionContext` with equal
  and unequal property maps.
- `RuleGraphMemoizationTest` stays, still under 60,000. The count should fall
  slightly below 2,563: five call sites build
  `BcDigests.rules(new DigestContext(Map.of("kind", "MGF1")))` with an identical
  context and currently produce five copies; they collapse into one.
- Full detection suite green in all four language modules.
- CBOM output for the test projects unchanged.

Known baseline: `SecureRandomGetInstanceTest` in the `java` module fails on
pristine `main` in some environments. Treat a failure there as pre-existing, not
a regression.

## Rollout

Five PRs, each green on its own:

1. **`engine`** — `DetectionRuleSet`, `ContextualDetectionRuleSet`, `RuleSets`,
   context `equals`/`hashCode`, plus their tests. Nothing else changes.
2. **`java`** — 136 classes, ~443 call sites, delete `Memoize`, new guard test.
3. **`python`** — 22 classes, ~33 call sites, delete `Memoize`.
4. **`go`** — 23 classes, ~78 call sites, delete `Memoize`.
5. **`csharp`** — 12 classes, ~17 call sites, guard test added for the first
   time.

PR 2 is the large one. Do the mechanical rewrite with a script, then read the
whole diff — a regex will not get the 9 contextual classes right.

Run `mvn spotless:apply` before each commit. Restore
`JsonCipherSuites` if the build truncates it.

## Follow-up, not in scope

`DetectionContext` gaining `equals` also makes a future rule-level dedupe
thinkable, but `MethodMatcher` identity still blocks it. No action.

## Acceptance criteria

- [ ] `DetectionRuleSet`, `ContextualDetectionRuleSet` and `RuleSets` exist in
      `engine` with `protected` build methods
- [ ] All 193 rule classes across the four modules extend a base; none exposes a
      public static rule accessor
- [ ] All ~571 call sites use `rulesOf(...)`
- [ ] `Memoize` and `MemoizeTest` deleted from `java`, `python` and `go`; never
      added to `csharp`
- [ ] Guard test present and green in all four modules
- [ ] `RuleGraphMemoizationTest` green, count at or below 2,563
- [ ] Full detection suite green; CBOM output unchanged
