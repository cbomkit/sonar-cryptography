from test.module import Foo

# f(a="hello", b=42) — a and b by keyword, c absent.
# a is positional in the rule; the engine reads arguments.get(0) = a="hello" and unwraps "hello".
# b satisfies withNamedMethodParameter("b", "int") by keyword-name lookup "b".
# c is optional and absent.
# → rule fires; no c child in detection store.
result = Foo.f(a="hello", b=42)
