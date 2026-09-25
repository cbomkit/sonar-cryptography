from test.module import Foo

# f(a="hello", b=42) — a and b by keyword, c absent.
# a was declared positional in the mixed rule, so this keyword call does not match it.
# b satisfies withNamedMethodParameter("b", "int") by keyword-name lookup "b".
# c is optional and absent.
# → the mixed rule does not fire; an all-named rule would fire without a c child.
result = Foo.f(a="hello", b=42)
