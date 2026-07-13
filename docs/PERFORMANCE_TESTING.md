# Performance & Heap Testing

This guide explains how to measure the plugin's runtime performance and heap usage,
primarily by scanning a large real-world project (**Keycloak**) end-to-end through
SonarQube. It exists to validate memory-sensitive engine work such as the call-stack
AST-detach fix (see `docs/superpowers/plans/2026-07-05-callstack-hooks-heap-reduction.md`).

There are two levels of testing:

| Level | What it is | When to use |
|---|---|---|
| **A. Self-contained JUnit harness** | `CallStackHeapPerfTest` — generates a synthetic cross-file corpus, scans it in-process, asserts detach invariants. No Docker, no network. | Quick, deterministic regression check. Runs in seconds–minutes. |
| **B. Keycloak end-to-end scan** | Full `mvn sonar:sonar` of Keycloak against a local SonarQube with the plugin installed. | Realistic heap/time numbers on a large project. Manual, ~10–15 min + setup. |

Start with **A** for a fast signal; use **B** to get true, large-project numbers.

---

## A. Self-contained JUnit harness (fast)

A `@Tag("performance")` test excluded from the default build. It generates N synthetic
cross-file crypto wrapper/caller pairs, compiles them to a classpath directory (so types
resolve and detections fire), scans them with `CheckVerifier`, and asserts that recorded
calls were detached (ASTs released) at `leaveFile`.

```bash
# default (~200 files, a few seconds)
mvn test -pl java -DexcludedGroups= -Dtest=CallStackHeapPerfTest

# heavy soak (scale the corpus)
mvn test -pl java -DexcludedGroups= -Dtest=CallStackHeapPerfTest -Dperf.corpus.files=3000
```

It prints a line like:

```
[callstack-perf] files=200 units=100 time=2325ms heapDeltaMB=83 \
    retainedWithTree=0 detached=367 total=367 buckets=2 ratio=1.000
```

- **`retainedWithTree`** — recorded calls still pinning a live AST. Must stay ~0.
- **`detached` / `ratio`** — calls converted to tree-free records. Ratio must stay high.
- **`heapDeltaMB`** — reported only, **never asserted** (a coarse whole-JVM number; at this
  synthetic scale it is *not* a reliable proxy for AST-pinning savings — the generated files
  are tiny, so pinned ASTs cost little in bytes). Use Keycloak (Part B) for real byte numbers.

The assertions (`ratio >= 0.9`, `retainedWithTree <= 10`) fail hard if AST-detaching regresses.

> **Why not CI?** It is `@Tag("performance")` and excluded from the default build via the
> surefire `<excludedGroups>performance</excludedGroups>` config in the root `pom.xml`.
> `mvn test` skips it; `-DexcludedGroups=` re-includes it.

---

## B. Keycloak end-to-end scan (real numbers)

### Prerequisites

- **Docker** + **Docker Compose** (for the local SonarQube + PostgreSQL).
- **JDK 17** to build this plugin; **the JDK Keycloak requires** to build Keycloak
  (currently **JDK 21** for `main`).
- **Maven 3.9+**.
- A full **JDK** (not just a JRE) on `PATH` for `jcmd` (used to sample heap — see Step 6).
- ~10 GB free RAM and a few GB disk. The scanner engine is capped at 6 GB in Step 5.

All commands below assume the plugin repo root is the current directory unless stated.

---

### Step 1 — Clone Keycloak

```bash
cd ~/Downloads          # or any working directory outside this repo
git clone --depth 1 https://github.com/keycloak/keycloak.git keycloak-main
cd keycloak-main
```

`--depth 1` is fine — we only need the source tree, not history.

---

### Step 2 — Build Keycloak (REQUIRED — compile so types resolve)

**This is the most important step.** The heap term only appears when detections actually
fire, and detections only fire when **types resolve**. A source-only scan (no compiled
classes / `sonar.java.binaries`) resolves nothing → 0 detections → the call-stack term is 0
and the measurement is meaningless.

Build Keycloak so every module produces `target/classes`:

```bash
# from the keycloak-main directory; uses Keycloak's Maven wrapper
./mvnw -q clean install -DskipTests -DskipITs
```

This is heavy (many modules) and needs Keycloak's required JDK. When it finishes you should
have compiled classes:

```bash
find . -type d -path '*target/classes' | wc -l    # expect dozens of dirs
```

If you only want a subset, you must still compile the modules you intend to scan (and their
dependencies), e.g. `./mvnw -pl services -am -DskipTests clean install`.

---

### Step 3 — Build the plugin and start SonarQube with it installed

SonarQube loads plugins **at startup**, so the JAR must be in place and the container
(re)started for changes to take effect.

**3a. Build the plugin JAR from your branch:**

```bash
# from the plugin repo root
mvn clean package -DskipTests
ls -la sonar-cryptography-plugin/target/sonar-cryptography-plugin-*.jar   # the artifact
```

> If `mvn` reformats/regenerates `mapper/.../JsonCipherSuites.java` (a known Spotless/fetch
> quirk), restore it before committing: `git checkout -- mapper/src/main/java/com/ibm/mapper/mapper/ssl/json/JsonCipherSuites.java`.

**3b. Deploy the JAR into the compose-mounted plugins directory:**

```bash
rm -f .SonarQube/plugins/sonar-cryptography-plugin-*.jar
cp sonar-cryptography-plugin/target/sonar-cryptography-plugin-*.jar .SonarQube/plugins/
```

(Do **not** copy the `*-sources.jar` or `original-*.jar`.)

**3c. Start SonarQube + PostgreSQL.** `docker-compose.yaml` uses `user: "${UID}"`, and in
zsh `UID` is a read-only variable that is *not* exported — if it is blank the container runs
as root and Elasticsearch/temp dirs get root-owned, causing permission crashes. Provide `UID`
explicitly via a `.env` file (Compose reads it automatically):

```bash
echo "UID=$(id -u)" > .env
docker compose up -d
```

Wait until it reports UP:

```bash
curl -s http://localhost:9000/api/system/status    # {"status":"UP", ...}
```

> If a previous run started as root and left root-owned volumes, wipe and retry:
> `docker compose down -v && echo "UID=$(id -u)" > .env && docker compose up -d`.

**3d. Verify the running instance loaded YOUR plugin** (the deployed JAR must contain your
changes, and SonarQube must have started *after* you copied it):

```bash
# the plugin's registered timestamp should be AFTER your JAR's build time
TOKEN=<your-token>   # from Step 4
curl -s -u "$TOKEN:" http://localhost:9000/api/plugins/installed \
  | python3 -c "import sys,json;[print(p['key'],p['version']) for p in json.load(sys.stdin)['plugins'] if 'crypto' in p['key']]"
# confirm the JAR carries your code:
unzip -l .SonarQube/plugins/sonar-cryptography-plugin-*.jar | grep CallContextStats
```

If you rebuild the plugin later, repeat 3a–3b then `docker compose restart sonarqube`.

---

### Step 4 — Create an analysis token

In the SonarQube UI (`http://localhost:9000`, default login `admin`/`admin`, change on first
login): **My Account → Security → Generate Token** (type: *Global Analysis Token*). Copy it.

```bash
export TOKEN=sqp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

---

### Step 5 — Run the scan with heap instrumentation

Run from the **Keycloak** directory (so `cbom.json` and scanner work dirs land there, not in
this repo).

**Important — the scanner forks a separate JVM.** `sonar-maven-plugin` downloads and runs the
**SonarScanner Engine** in a child JVM under `~/.sonar/cache/...` — this is where the plugin,
`CallStackAgent`, and the heap actually live. It does **not** inherit `MAVEN_OPTS`. To cap and
instrument the *right* JVM, pass `-Dsonar.scanner.javaOpts`.

```bash
cd ~/Downloads/keycloak-main

mvn org.sonarsource.scanner.maven:sonar-maven-plugin:sonar \
  -Dsonar.projectKey=keycloak \
  -Dsonar.projectName='keycloak' \
  -Dsonar.host.url=http://localhost:9000 \
  -Dsonar.token=$TOKEN \
  -Dsonar.scanner.javaOpts="-Xms512m -Xmx6g -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=/tmp"
```

- `-Xmx6g` is deliberate: the pre-fix code drove this scan past **7 GB and never finished**,
  so completing under 6 GB is itself a pass/fail signal.
- A heap dump is written to `/tmp` if it OOMs, for post-mortem analysis.

> Avoid embedding `-Xlog:gc*:file=...` in `sonar.scanner.javaOpts`; the multi-colon argument
> is mangled when passed through the scanner. Sample heap externally instead (Step 6).

---

### Step 6 — Sample the engine heap during the scan

While the scan runs, sample the **engine** JVM's heap with `jcmd` (from a full JDK — the
scanner's bundled JRE has no `jcmd`). Run this in a second terminal *after* the scan reaches
its analysis phase:

```bash
JCMD=$(command -v jcmd)                     # must be a JDK jcmd
OUT=/tmp/keycloak-heap-samples.csv
echo "epoch,rss_mb,heap_used_mb,heap_total_mb,meta_used_mb" > "$OUT"
while true; do
  E=$(pgrep -f sonar-scanner-engine-shaded | head -1)
  [ -z "$E" ] && break                      # engine gone -> scan finished
  RSS=$(ps -o rss= -p "$E" 2>/dev/null | tr -d ' ')
  INFO=$("$JCMD" "$E" GC.heap_info 2>/dev/null)
  HU=$(echo "$INFO" | grep -oE 'used [0-9]+K' | head -1 | grep -oE '[0-9]+')
  HT=$(echo "$INFO" | grep -oE 'total [0-9]+K' | head -1 | grep -oE '[0-9]+')
  MU=$(echo "$INFO" | grep Metaspace | grep -oE 'used [0-9]+K' | grep -oE '[0-9]+')
  [ -n "$RSS" ] && echo "$(date +%s),$((RSS/1024)),$((${HU:-0}/1024)),$((${HT:-0}/1024)),$((${MU:-0}/1024))" >> "$OUT"
  sleep 15
done

# peak heap used / committed / RSS across the run:
tail -n +2 "$OUT" | awk -F, 'BEGIN{u=0;c=0;r=0}
  $3>u{u=$3} $4>c{c=$4} $2>r{r=$2}
  END{printf "peak heap_used=%d MB  peak committed=%d MB  peak RSS=%d MB  samples=%d\n",u,c,r,NR}'
```

---

### Step 7 — Interpret the results

Confirm the scan actually exercised the plugin:

```bash
grep -E "ANALYSIS SUCCESSFUL|CBOM was successfully generated" <scan-output>
```

A CBOM (`cbom.json` in the scan CWD) means detections fired, so the call-stack term was
exercised.

**What good looks like (with the AST-detach fix, measured on Keycloak `main`, SonarQube 26.1,
93 modules / ~8200 files):**

| Metric | Pre-fix (old) | With AST-detach fix |
|---|---|---|
| Outcome | ~7 GB **and climbing, did not finish** | **ANALYSIS SUCCESSFUL** in ~11 min |
| Under `-Xmx6g` | would OOM | completed, no OOM |
| Peak heap used | 7 GB+ (linear, no plateau) | ~4.6 GB (oscillating, GC reclaims) |

- **Healthy:** `heap_used` **oscillates** — rises then drops as G1 reclaims — and the scan
  completes. The post-GC floor may grow modestly but the run finishes under the cap.
- **Regression:** `heap_used` climbs **monotonically** toward the cap and OOMs (heap dump in
  `/tmp`), or the scan never finishes. That signals AST pinning (or another unbounded term)
  has returned.

Note the residual ~4.6 GB is *not* the call-stack AST term (that is eliminated — see the
synthetic harness's `retainedWithTree=0`); it is SonarQube's baseline analysis cost plus the
CBOM nodes accumulated for the whole scan (`JavaAggregator.detectedNodes`). `jcmd`'s
`heap_used` includes uncollected garbage, so the true retained set sits at the GC *floors*,
below the sampled peak.

---

### Cleanup

```bash
# stop SonarQube (keep data)          # or: down -v to wipe volumes
docker compose down

# remove scan artifacts from the Keycloak dir
rm -f ~/Downloads/keycloak-main/cbom.json
rm -rf ~/Downloads/keycloak-main/.scannerwork
```

---

## C. Post-detach floor attribution (H1)

AST-detach removed the dominant AST-pinning heap term, but the post-GC floor still grows over a
scan (observed ~1.6 → ~3.4 GB). This procedure attributes that residual to one of three
populations so we know whether the call-stack still needs trimming (H2) or whether retained CBOM
nodes dominate (a separate follow-up).

### Two signals

**1. In-process population counts (cheap).** At end of scan the plugin logs, at DEBUG:

```
[heap-attribution] detectedNodes=<n> detachedCalls=<n> totalCalls=<n> callStackBuckets=<n>
```

Enable DEBUG for the plugin (e.g. `-Dsonar.log.level=DEBUG` on the scanner, or the analysis
`sonar.verbose=true`) and read the line from the scanner log. The fast local proxy is
`CallStackHeapPerfTest`, whose report line now also prints `detectedNodes=<n>` (note: `0` in that
harness — it runs with `isInventory=false`, so CBOM nodes are not aggregated there; the count is
meaningful only on a real inventory scan).

Counts size the *populations*, not their bytes — a small count of heavy objects can still
dominate. Use them to spot which population grows, then confirm bytes with the histogram below.

**2. Byte attribution via `jmap` (decisive).** During a constrained-heap Keycloak scan (see
section B), capture a live histogram near the end of analysis:

```bash
# find the scanner JVM pid (the surefire/scanner java process running the analysis)
jps -l
# live histogram (forces a GC first), sorted by retained bytes
jmap -histo:live <pid> > histo.txt
```

Bucket the top entries of `histo.txt` into the three sources:

| Bucket | Classes to sum in `histo.txt` |
|---|---|
| Retained CBOM nodes | `com.ibm.mapper.model.**` (e.g. `Algorithm`, `Key`, `Property`, `MessageDigest`, …) and their child `HashMap`/`HashMap$Node` share |
| Detached call-stack | `com.ibm.engine.callstack.DetachedCall`, `...callstack.ArgSnapshot`, `...callstack.ResolvedSnapshotValue` |
| Residual Tree / hooks | `org.sonar.**Tree*` still live + `com.ibm.engine.hooks.**` |

Sample two or three histograms as the scan progresses to see which bucket *grows* (the floor is
about accumulation, not a one-time cost).

### Decision — measured 2026-07-06 (Keycloak `main`, 94 compiled modules, SonarQube 26.1, `-Xmx6g`)

Scan outcome: **ANALYSIS SUCCESSFUL** in ~14 min, CBOM generated (108 detected assets → 68
components), no OOM; post-GC heap floor oscillated and ended ~2.9–3.4 GB (healthy — G1 reclaims,
no monotonic climb). Attribution from live `GC.class_histogram` (post-full-GC) sampled early /
mid / late in the run:

| Population | early | mid | late (near end) |
|---|---|---|---|
| Retained CBOM nodes (`com.ibm.mapper.**`) | ~0 | 0.01 MB (484) | **0.02 MB (824 inst)** |
| Detached call-stack (`com.ibm.engine.callstack.**`) | ~0 | 7.6 MB (291k) | **15.6 MB (594k inst)** |
| Hooks (`com.ibm.engine.hooks.**`) | ~0 | 0.001 MB | **~1 KB (1376 inst)** |
| **Plugin total (`com.ibm.**`)** | ~0 | 14.2 MB | **28.4 MB** |
| **Whole heap floor** | 0.05 GB | 1.55 GB | **2.90 GB** |

The ~2.9 GB floor is overwhelmingly **SonarQube / ECJ baseline**, not plugin state — the top
retained classes are `byte[]` (332 MB), `HashMap$Node` (251 MB), `Object[]` (219 MB), `char[]`
(210 MB), `ArrayList` (176 MB), and sonar-java/ECJ semantic objects (`InternalPosition` 152 MB,
`InternalSyntaxToken` 122 MB, `MethodBinding` 95 MB, `InternalRange` 76 MB).

**Outcome — the original hypothesis is disproven.** The floor growth (~1.6 → ~3.4 GB) is *not*
`JavaAggregator.detectedNodes`: retained CBOM nodes are **negligible (~25 KB, 824 instances)**.
The entire plugin footprint is **~28 MB (~1 % of the floor)**, and the floor growth tracks
SonarQube's own accumulating semantic model / AST of the module under analysis — which the plugin
cannot reduce. Within the plugin the **call-stack dominates** (15.6 MB vs. 0.02 MB) and grows
linearly/unbounded (291k → 594k records mid→late), but AST-detach keeps each record tiny, so the
absolute heap cost is small.

**H2 routing (revised by this measurement):**
- **No `detectedNodes` spec.** CBOM-node retention is not a heap problem — drop that candidate.
- **No heap-motivated retention cap.** 594k detached records ≈ 15.6 MB is not a memory risk; the
  cap (old Task 5) is unjustified on heap grounds — defer/drop it.
- **Eligibility filter → justify on CPU, not heap.** Skipping library calls still avoids building
  their expensive detached form (`buildDetachedCall`), so fold it into the **throughput track
  (C1/C2)**, not a heap spec. Net: the heap track is effectively closed by this measurement.

> Note: signal 1 (the `[heap-attribution]` DEBUG line) does not surface in the Maven scanner
> console even with `sonar.verbose=true` — the scanner does not route plugin `LOGGER.debug` there
> (the INFO `Detected Assets` statistics line does print). The `jmap`/`jcmd` histogram (signal 2)
> is the reliable attribution path; use it directly.

> Note on H2's eligibility filter: the predicate cannot be derived from `methodSymbol().declaration()`
> — cross-file *user* calls resolve via `sonar.java.binaries` and have a null declaration, exactly
> like library calls (see the comment in `JavaLanguageSupport.isDetachableCall`). The discriminator
> must be pinned empirically against the `crossfile/` fixtures before the filter is written.

---

## Gotchas quick reference

- **0 detections / term is 0** → Keycloak wasn't compiled. Rebuild (Step 2); the scan needs
  resolvable types (`sonar.java.binaries`).
- **Heap cap/logging seem ignored** → you set `MAVEN_OPTS`. The analysis runs in the forked
  scanner-engine JVM; use `-Dsonar.scanner.javaOpts` (Step 5).
- **`jcmd` not found / can't attach** → the scanner's bundled JRE lacks `jcmd`; use a full JDK's
  `jcmd` (`GC.heap_info` attaches across compatible versions).
- **Container permission crashes / runs as root** → `UID` was unset (zsh read-only). Create
  `.env` with `UID=$(id -u)` and, if it already ran as root, `docker compose down -v` first.
- **Plugin changes not reflected** → rebuild JAR, copy into `.SonarQube/plugins/`, then
  `docker compose restart sonarqube` (plugins load at startup). Verify with the
  `api/plugins/installed` check in Step 3d.
