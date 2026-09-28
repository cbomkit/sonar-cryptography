from test.module import Foo

# f("hello", "42") — b is a str literal but the rule declares withNamedMethodParameter("b","int").
# b is found via positional fallback at index 1; the named-parameter type-check resolves "42" as
# str and rejects it against "int". Because b is required (not optional), the rule returns early.
# → rule does NOT fire.
result = Foo.f("hello", "42")
