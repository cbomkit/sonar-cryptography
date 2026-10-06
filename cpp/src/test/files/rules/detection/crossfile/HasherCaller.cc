class Hasher {
  public:
    Hasher(const char *name);
};

// The constructor calls are recorded while scanning this file, before the hook of the
// constructor, defined in HasherDefinition.cc, is created.
void name_held_by_a_variable() {
    const char *name = "SHA224";
    Hasher hasher(name);
}

void braced_argument() {
    Hasher hasher{"SHA384"};
}
