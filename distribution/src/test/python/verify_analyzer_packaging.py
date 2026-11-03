"""Verify the licences, legal files, sources and contents of a variant JAR.

Usage:
    verify_analyzer_packaging.py --variant {plugin,plugin-with-go,library} JAR

The checks follow the variants plan
(docs/superpowers/plans/2026-10-30-unified-analyzer-variants.md, step 7):

* plugin: no SonarSource analyzer is bundled; Java and Python come from SonarQube
  (Plugin-RequirePlugins), there is no Go and no SSAL text.
* plugin-with-go: as plugin, plus a relocated sonar-go with its SSALv1 text,
  legal files, sources JAR and complete release source.
* library: the LGPL-3.0 sonar-java and sonar-python (and the EPL-2.0
  jdt-package) are bundled whole with their legal files and sources; no Go, no
  Plugin-RequirePlugins and no SSAL text.

For every variant, every bundled third-party artifact whose licence is not
Apache, MIT or BSD must be named in the notices, and its licence text must be in
META-INF/third-party/. The artifacts come from target/bundled-dependencies.txt,
written by the build (dependency:list).
"""

import argparse
from io import BytesIO
from pathlib import Path
import re
import xml.etree.ElementTree as ET
from zipfile import ZipFile

NAMESPACE = {"m": "http://maven.apache.org/POM/4.0.0"}
ROOT = Path(__file__).resolve().parents[4]
DISTRIBUTION = ROOT / "distribution"
THIRD_PARTY = "META-INF/third-party/"
SOURCES_DIR = THIRD_PARTY + "analyzer-sources/"
LEGAL_DIR = THIRD_PARTY + "analyzers/"
NOTICES_DIR = THIRD_PARTY + "notices/"
SERVICE = "META-INF/services/com.ibm.output.ILanguageModule"
SOURCES_NAME = re.compile(r"^(?P<artifact>.+)-(?P<version>\d[\w.]*)-sources\.jar$")
# "SSAL" is matched as a word and case-sensitively: lower-case "ssal" is a common
# Hungarian suffix, and Unicode data files contain names such as "WASSALLAM".
FORBIDDEN = re.compile(rb"\bSSAL(v1)?\b|(?i:source[- ]available licen[cs]e)")
# The SAX licence is a public-domain dedication; the W3C software licence is permissive.
PERMISSIVE = re.compile(
    r"apache|\bmit\b|\bbsd\b|public domain|\bcc0\b|\bSAX License\b|\bW3C License\b",
    re.IGNORECASE,
)
# Licence family -> the texts that must be in META-INF/third-party/.
LICENCE_TEXTS = {
    "LGPL": ("LGPL-3.0.txt", "GPL-3.0.txt"),
    "EPL": ("EPL-2.0.txt",),
    "SSAL": ("SSALv1.txt",),
}
SCOPES = {"compile", "runtime", "provided", "system", "test"}

VARIANTS = {
    "plugin": {
        "directory": "plugin",
        "languages": ["Java", "Python", "C#"],
        "relocations": {},
    },
    "plugin-with-go": {
        "directory": "plugin-with-go",
        "languages": ["Java", "Python", "C#", "Go"],
        "relocations": {
            "org/sonar/go/": "com/ibm/shaded/org/sonar/go/",
            "org/sonar/plugins/go/": "com/ibm/shaded/org/sonar/plugins/go/",
            "org/sonarsource/analyzer/commons/": "com/ibm/shaded/org/sonarsource/analyzer/commons/",
        },
    },
    "library": {
        "directory": "library",
        "languages": ["Java", "Python", "C#"],
        "relocations": {},
    },
}
LANGUAGE_CLASSES = {
    "Java": "com.ibm.plugin.JavaLanguageModule",
    "Python": "com.ibm.plugin.PythonLanguageModule",
    "C#": "com.ibm.plugin.CSharpLanguageModule",
    "Go": "com.ibm.plugin.GoLanguageModule",
}


def root_property(name):
    properties = ET.parse(ROOT / "pom.xml").find("m:properties", NAMESPACE)
    element = properties.find("m:" + name, NAMESPACE)
    assert element is not None, "Missing root property " + name
    return element.text.strip()


def manifest_of(data):
    """Parse a MANIFEST.MF, joining continuation lines."""
    text = data.decode().replace("\r\n", "\n").replace("\n ", "")
    return dict(line.split(": ", 1) for line in text.splitlines() if ": " in line)


def is_class(name):
    return (
        name.endswith(".class")
        and not name.startswith("META-INF/")
        and not name.endswith("module-info.class")
    )


def pom_path(repository, group, artifact, version):
    return (
        repository / group.replace(".", "/") / artifact / version
        / (artifact + "-" + version + ".pom")
    )


def pom_licence(repository, pom):
    """Return the licence names declared by a POM or its nearest parent that has one."""
    while pom is not None and pom.exists():
        project = ET.parse(pom).getroot()
        # Old POMs such as xml-apis 1.4.01 have no XML namespace.
        for element in project.iter():
            element.tag = element.tag.rsplit("}", 1)[-1]
        names = [
            element.text.strip()
            for element in project.findall("licenses/license/name")
            if element.text
        ]
        if names:
            return names
        parent = project.find("parent")
        if parent is None:
            return []
        group, artifact, version = (
            parent.find(key).text.strip() for key in ("groupId", "artifactId", "version")
        )
        pom = pom_path(repository, group, artifact, version)
    return []


def licence_family(names):
    """Map POM licence names to a family that needs a notice, or None if permissive."""
    joined = " / ".join(names)
    if re.search(r"\bSSAL|source[- ]available", joined, re.IGNORECASE):
        return "SSAL"
    if re.search(r"LGPL|Lesser General Public", joined, re.IGNORECASE):
        return "LGPL"
    if re.search(r"\bEPL\b|Eclipse Public", joined, re.IGNORECASE):
        return "EPL"
    if names and all(PERMISSIVE.search(name) for name in names):
        return None
    # Dual licences such as "Apache / LGPL": one permissive option is enough.
    if any(PERMISSIVE.search(name) for name in names) and "GPL" not in joined:
        return None
    raise AssertionError("Unknown or unsupported licence: " + (joined or "none declared"))


def read_dependencies(path):
    """Parse the dependency:list output into (group, artifact, version, file) tuples."""
    assert path.exists(), "Missing dependency list " + str(path) + " (run the build first)"
    dependencies = []
    for line in path.read_text().splitlines():
        line = line.strip().split(" -- ")[0]
        parts = line.split(":")
        if len(parts) < 6:
            continue
        scope_index = next(
            (i for i in range(4, len(parts)) if parts[i] in SCOPES), None
        )
        if scope_index is None:
            continue
        dependencies.append(
            (parts[0], parts[1], parts[scope_index - 1], Path(":".join(parts[scope_index + 1:])))
        )
    assert dependencies, "Empty dependency list " + str(path)
    return dependencies


def relocated(name, relocations):
    for prefix, target in relocations.items():
        if name.startswith(prefix):
            return target + name[len(prefix):]
    return name


def classes_of(jar_file):
    if not jar_file.is_file():
        return set()
    with ZipFile(jar_file) as jar:
        return {name for name in jar.namelist() if is_class(name)}


def assert_no_forbidden_text(name, data):
    assert not FORBIDDEN.search(data), "SSAL text found in " + name
    if name.endswith((".jar", ".zip")):
        with ZipFile(BytesIO(data)) as nested:
            for entry in nested.namelist():
                if not entry.endswith("/"):
                    assert_no_forbidden_text(name + "!" + entry, nested.read(entry))


def assert_same(packaged, entry, path):
    assert entry in packaged.namelist(), "Missing " + entry
    assert packaged.read(entry) == path.read_bytes(), "Changed " + entry + " (expected " + str(path) + ")"


def upstream_legal_files(original):
    return [
        name
        for name in original.namelist()
        if not name.endswith("/") and (
            "license" in name.lower()
            or "notice" in name.lower()
            or name.startswith("about_files/")
            or name == "about.html"
        )
    ]


class Checker:
    def __init__(self, jar, variant, repository, dependencies):
        self.jar = jar
        self.variant = variant
        self.config = VARIANTS[variant]
        self.repository = repository
        self.dependencies = read_dependencies(dependencies)
        self.zip = ZipFile(jar)
        self.names = self.zip.namelist()
        self.name_set = set(self.names)
        self.manifest = manifest_of(self.zip.read("META-INF/MANIFEST.MF"))
        self.notice = self.zip.read("META-INF/THIRD-PARTY-NOTICES.txt").decode()
        self.all_notices = self.notice + "".join(
            self.zip.read(name).decode()
            for name in self.names
            if name.startswith(NOTICES_DIR) and not name.endswith("/")
        )
        self.resources = DISTRIBUTION / self.config["directory"] / "src/main/resources" / THIRD_PARTY
        self.shared = DISTRIBUTION / "src/shared-resources" / THIRD_PARTY
        self.passed = []

    def ok(self, message):
        self.passed.append(message)

    def bundled_dependencies(self):
        """The third-party artifacts of which at least one class is in the JAR."""
        jar_classes = {name for name in self.names if is_class(name)}
        result = []
        for group, artifact, version, file in self.dependencies:
            if group == "com.ibm":
                continue
            classes = classes_of(file)
            kept = {c for c in classes if relocated(c, self.config["relocations"]) in jar_classes}
            if kept:
                result.append((group, artifact, version, file, len(classes), len(kept)))
        return result

    # ------------------------------------------------------------------ all variants

    def check_common(self):
        assert len(self.names) == len(self.name_set), "Duplicate JAR entries"
        files = [name for name in self.names if not name.endswith("/")]
        lower = {}
        for name in files:
            other = lower.setdefault(name.lower(), name)
            assert other == name, "Entries differ only in case: " + other + ", " + name
        self.ok("no duplicate entries, also case-insensitively")

        assert_same(self.zip, "META-INF/LICENSE.txt", ROOT / "LICENSE.txt")
        assert "${" not in self.all_notices, "Unresolved Maven properties in the notices"
        self.ok("LICENSE.txt and notices")

        assert self.manifest.get("Plugin-Key") == "crypto", "Plugin-Key"
        plugin_class = self.manifest.get("Plugin-Class")
        assert plugin_class == "com.ibm.plugin.CryptographyPlugin", "Plugin-Class " + str(plugin_class)
        assert plugin_class.replace(".", "/") + ".class" in self.name_set, "Plugin class missing"
        services = [
            line.strip()
            for line in self.zip.read(SERVICE).decode().splitlines()
            if line.strip() and not line.startswith("#")
        ]
        expected = [LANGUAGE_CLASSES[language] for language in self.config["languages"]]
        assert sorted(services) == sorted(expected), "Language modules " + str(services)
        for service in services:
            assert service.replace(".", "/") + ".class" in self.name_set, "Missing " + service
        self.ok("manifest, plugin class and language modules " + ", ".join(self.config["languages"]))

        assert not any(name.startswith("com/google/googlejavaformat/") for name in self.names), (
            "google-java-format bundled"
        )
        self.ok("no google-java-format")

        self.check_csharp_parser()
        self.check_bundled_licences()

    def check_csharp_parser(self):
        assert_same(self.zip, THIRD_PARTY + "EPL-2.0.txt", self.shared / "EPL-2.0.txt")
        properties = "META-INF/maven/io.github.fynnth/cbomkit-csharp-parser/pom.properties"
        if properties in self.name_set:
            version = re.search(r"^version=(.+)$", self.zip.read(properties).decode(), re.M)[1].strip()
        else:
            version = next(v for g, a, v, _ in self.dependencies if a == "cbomkit-csharp-parser")
        notice = self.zip.read(NOTICES_DIR + "cbomkit-csharp-parser.txt").decode()
        assert "cbomkit-csharp-parser " + version in notice, "Parser notice names another version"
        url = (
            "https://repo.maven.apache.org/maven2/io/github/fynnth/cbomkit-csharp-parser/"
            + version + "/cbomkit-csharp-parser-" + version + "-sources.jar"
        )
        assert url in notice, "Parser source URL missing"
        assert "https://github.com/fynnth/cbomkit-csharp-parser" in notice, "Parser project missing"
        assert "EPL-2.0" in self.notice and "notices/cbomkit-csharp-parser.txt" in self.notice, (
            "THIRD-PARTY-NOTICES.txt does not refer to the parser notice"
        )
        self.ok("EPL-2.0.txt and the C# parser notice (version " + version + ")")

    def check_bundled_licences(self):
        bundled = self.bundled_dependencies()
        needing_notice = []
        for group, artifact, version, _, _, _ in bundled:
            names = pom_licence(self.repository, pom_path(self.repository, group, artifact, version))
            try:
                family = licence_family(names)
            except AssertionError as error:
                raise AssertionError(group + ":" + artifact + ":" + version + ": " + str(error))
            if family is None:
                continue
            needing_notice.append(artifact)
            assert re.search(r"\b" + re.escape(artifact) + r"\b", self.all_notices), (
                group + ":" + artifact + " (" + ", ".join(names) + ") is not named in the notices"
            )
            for text in LICENCE_TEXTS[family]:
                assert THIRD_PARTY + text in self.name_set, (
                    "Missing licence text " + text + " for " + artifact
                )
        self.ok(
            str(len(bundled)) + " bundled third-party artifacts; "
            + str(len(needing_notice)) + " not Apache/MIT/BSD, all named with licence texts"
        )
        return bundled

    # ------------------------------------------------------------------ variants

    def check_no_analyzer_internals(self, allowed=()):
        prefixes = (
            "org/sonar/java/", "org/sonar/python/", "org/sonar/go/", "org/sonar/plugins/go/",
            "org/sonarsource/", "org/sonar/plugins/java/", "org/sonar/plugins/python/",
        )
        prefixes = tuple(p for p in prefixes if p not in allowed)
        found = [name for name in self.names if name.startswith(prefixes)]
        assert not found, "Analyzer classes bundled: " + found[0]

    def check_require_plugins(self):
        expected = (
            "java:" + root_property("sonar.java.minVersion")
            + ",python:" + root_property("sonar.python.minVersion")
        )
        assert self.manifest.get("Plugin-RequirePlugins") == expected, (
            "Plugin-RequirePlugins " + str(self.manifest.get("Plugin-RequirePlugins"))
        )
        self.ok("Plugin-RequirePlugins " + expected)

    def check_no_forbidden_text(self):
        for name in self.names:
            if not name.endswith("/"):
                assert_no_forbidden_text(name, self.zip.read(name))
        self.ok("no SSAL text, also in nested archives")

    def check_no_go(self):
        go = [
            name for name in self.names
            if name.startswith(("com/ibm/engine/language/go/", "com/ibm/shaded/"))
            or "GoLanguageModule" in name or "sonar-go" in name
        ]
        assert not go, "Go bundled: " + go[0]
        assert "go" not in self.manifest.get("Plugin-RequiredForLanguages", "").split(","), (
            "go in Plugin-RequiredForLanguages"
        )
        self.ok("no Go")

    def check_plugin(self):
        self.check_no_analyzer_internals()
        self.check_require_plugins()
        assert not any(name.startswith((SOURCES_DIR, LEGAL_DIR)) for name in self.names), (
            "Analyzer sources or legal files bundled"
        )
        self.ok("no analyzer classes, sources or legal files")
        self.check_no_go()
        self.check_no_forbidden_text()

    def check_plugin_with_go(self):
        self.check_no_analyzer_internals()
        self.check_require_plugins()
        assert "go" in self.manifest["Plugin-RequiredForLanguages"].split(","), "go not required"
        for prefix in VARIANTS["plugin-with-go"]["relocations"].values():
            assert any(name.startswith(prefix) and is_class(name) for name in self.names), (
                "No relocated classes under " + prefix
            )
        assert any(n.startswith("com/ibm/engine/language/go/") for n in self.names), "No Go engine"
        self.ok("relocated sonar-go, Go engine and plugin classes, go in RequiredForLanguages")
        assert_same(self.zip, THIRD_PARTY + "SSALv1.txt", self.resources / "SSALv1.txt")
        self.check_go_sources()

    def check_go_sources(self):
        version = root_property("sonar.go.version")
        revision = root_property("sonar.go.source.revision")
        origin = root_property("sonar.go.source.origin-revision")
        artifact = "sonar-go-plugin"
        coordinate = "org.sonarsource.go:" + artifact + ":" + version
        assert coordinate in self.notice, "Missing coordinate " + coordinate
        assert revision in self.notice and origin in self.notice, "Missing Go source provenance"
        directory = self.repository / "org/sonarsource/go" / artifact / version
        source_name = artifact + "-" + version + "-sources.jar"
        assert source_name in self.notice, "Missing source URL " + source_name
        assert_same(self.zip, SOURCES_DIR + source_name, directory / source_name)
        prefix = LEGAL_DIR + artifact + "-" + version + "-jar/"
        assert prefix in self.notice, "Wrong legal-file directory in the notice"
        with ZipFile(directory / (artifact + "-" + version + ".jar")) as original:
            assert "Implementation-Build: " + origin in original.read("META-INF/MANIFEST.MF").decode().replace("\r\n ", ""), (
                "Go dependency changed: update the matching release source revisions"
            )
            legal_files = upstream_legal_files(original)
            assert legal_files, "No upstream legal files: " + artifact
            for name in legal_files:
                assert self.zip.read(prefix + name) == original.read(name), "Changed " + prefix + name
        archive_name = "sonar-go-" + version + "-" + revision + "-source.zip"
        archive = self.zip.read(SOURCES_DIR + archive_name)
        with ZipFile(BytesIO(archive)) as source:
            assert source.comment.decode() == revision, "Wrong Go source revision"
            root = "sonar-go-" + revision + "/"
            for path in (
                "LICENSE.txt",
                "sonar-go-commons/src/main/java/org/sonar/go/converter/GoConverter.java",
                "sonar-go-to-slang/main.go",
                "sonar-go-to-slang/goparser.go",
                "sonar-go-to-slang/generate_source.go",
                "sonar-go-to-slang/mapping_generated.go",
                "sonar-go-to-slang/go.mod",
                "sonar-go-to-slang/go.sum",
                "sonar-go-to-slang/make.sh",
                "build-logic/common/build.gradle.kts",
            ):
                assert source.read(root + path), "Missing Go release source: " + path
            with ZipFile(directory / source_name) as published:
                java_files = [name for name in published.namelist() if name.endswith(".java")]
                assert java_files, "No published Go Java sources to compare"
                for name in java_files:
                    assert source.read(root + "sonar-go-plugin/src/main/java/" + name) == published.read(name), (
                        "Go release source mismatch: " + name
                    )
        self.ok("SSALv1.txt, sonar-go legal files, sources JAR and complete release source")

    def check_library(self):
        assert "Plugin-RequirePlugins" not in self.manifest, "Plugin-RequirePlugins in the library"
        self.ok("no Plugin-RequirePlugins")
        self.check_no_go()
        for text in ("LGPL-3.0.txt", "GPL-3.0.txt"):
            assert_same(self.zip, THIRD_PARTY + text, self.resources / text)
        self.ok("LGPL-3.0.txt and GPL-3.0.txt")

        # Every bundled sources JAR: allowed licence, unchanged, named in the notice.
        sources = {}
        for name in self.names:
            match = SOURCES_NAME.match(name[len(SOURCES_DIR):]) if name.startswith(SOURCES_DIR) else None
            if not match:
                continue
            artifact, version = match["artifact"], match["version"]
            matches = list((self.repository / "org/sonarsource").glob("*/" + artifact + "/" + version))
            assert len(matches) == 1, "Cannot locate " + artifact + ":" + version
            directory = matches[0]
            family = licence_family(pom_licence(self.repository, directory / (artifact + "-" + version + ".pom")))
            expected = "EPL" if artifact == "jdt-package" else "LGPL"
            assert family == expected, artifact + " licence is " + str(family) + ", expected " + expected
            assert self.zip.read(name) == (directory / (artifact + "-" + version + "-sources.jar")).read_bytes(), (
                "Changed source JAR: " + name
            )
            assert re.search(r"\b" + re.escape(artifact) + r"\b", self.notice), "Not in the notice: " + artifact
            assert version in self.notice, "Version not in the notice: " + artifact + " " + version
            sources[artifact] = version
        assert sources, "No analyzer sources bundled"

        # Every bundled SonarSource artifact: all classes kept, sources bundled (F7, V4b).
        bundled = [b for b in self.bundled_dependencies() if b[0].startswith("org.sonarsource.")]
        for group, artifact, version, _, total, kept in bundled:
            assert kept == total, artifact + ": " + str(kept) + " of " + str(total) + " classes bundled"
            assert sources.get(artifact) == version, "Bundled without sources: " + artifact
        self.ok(str(len(bundled)) + " SonarSource artifacts bundled whole, each with its sources")

        for language in ("java", "python"):
            version = root_property("sonar." + language + ".version")
            artifact = "sonar-" + language + "-plugin"
            assert sources.get(artifact) == version, "Missing sources: " + artifact
            assert sources.get(language + "-frontend") == version, "Missing " + language + "-frontend sources"
            directory = self.repository / "org/sonarsource" / language / artifact / version
            prefix = LEGAL_DIR + artifact + "-" + version + "-jar/"
            with ZipFile(directory / (artifact + "-" + version + ".jar")) as original:
                assert "Plugin-License: GNU LGPL 3" in original.read("META-INF/MANIFEST.MF").decode(), (
                    artifact + " is not LGPL"
                )
                for name in upstream_legal_files(original):
                    assert self.zip.read(prefix + name) == original.read(name), "Changed " + prefix + name
        jdt = [n for n in self.names if re.match(LEGAL_DIR + r"jdt-package-[\d.]+-jar/about\.html$", n)]
        assert jdt, "jdt-package about.html missing"
        assert any(n.startswith("org/eclipse/jdt/") for n in self.names), "No jdt classes"
        assert re.search(r"jdt-package[\s\S]*EPL-2\.0", self.notice), "jdt-package not listed as EPL-2.0"
        self.ok("sonar-java and sonar-python legal files and frontends, jdt-package (EPL-2.0)")
        self.check_no_forbidden_text()

    def run(self):
        self.check_common()
        {
            "plugin": self.check_plugin,
            "plugin-with-go": self.check_plugin_with_go,
            "library": self.check_library,
        }[self.variant]()
        print("Verified " + self.variant + " JAR " + str(self.jar) + ":")
        for message in self.passed:
            print("  - " + message)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("jar", type=Path)
    parser.add_argument("--variant", required=True, choices=sorted(VARIANTS))
    parser.add_argument("--repository", type=Path, default=Path.home() / ".m2/repository")
    parser.add_argument(
        "--dependencies", type=Path,
        help="dependency:list output; default: bundled-dependencies.txt next to the JAR",
    )
    arguments = parser.parse_args()
    Checker(
        arguments.jar, arguments.variant, arguments.repository,
        arguments.dependencies or arguments.jar.parent / "bundled-dependencies.txt",
    ).run()
