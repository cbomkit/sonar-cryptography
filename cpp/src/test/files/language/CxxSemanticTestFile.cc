enum Mode { FAST = 3, SLOW };
enum class Strictness { STRICT, LENIENT };

struct Settings {
    const char *name;
};

void values(int condition, struct Settings settings, const char *parameter) {
    const char *local = "initial";
    local = "reassigned";
    const char *assigned;
    v("plain");
    v(L"wide");
    v(u"utf16");
    v(U"utf32");
    v(u8"utf8");
    v(R"(raw)");
    v("con" "cat");
    v('c');
    v(42);
    v(42u);
    v(0x10);
    v(0x80000000);
    v(0b101);
    v(010);
    v(1.5f);
    v(1'000);
    v(5000000000);
    v(0e0);
    v(true);
    v(false);
    v(nullptr);
    v((24));
    v(condition ? "either" : "or");
    v(1 ? "chosen" : "other");
    v((const char *) "cast");
    v(static_cast<int>(7));
    v(2 * 1024);
    v(TLS1_2_VERSION);
    v(assigned = "assigned");
    v(FAST);
    v(SLOW);
    v(Strictness::LENIENT);
    v(local);
    v(settings.name);
    v(parameter);
}
