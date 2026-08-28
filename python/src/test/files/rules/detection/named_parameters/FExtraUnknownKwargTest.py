from test.module import Foo

# f("hello", 42, "yes", d=0) — matching args plus one completely unknown keyword argument.
# a satisfies withMethodParameter("str") at index 0.
# b satisfies withNamedMethodParameter("b", "int") via positional fallback at index 1.
# c satisfies withOptionalNamedMethodParameter("c", "str") via positional fallback at index 2.
# d=0 sits at index 3; no rule parameter ever references it, so it is silently ignored.
# → rule fires; c is captured.
result = Foo.f("hello", 42, "yes", d=0)
