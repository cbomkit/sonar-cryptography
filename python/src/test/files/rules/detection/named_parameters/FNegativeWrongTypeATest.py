from test.module import Foo

# f(42, 42) — a is an int literal but the rule declares withMethodParameter("str").
# The positional type-check loop resolves arguments.get(0) as int and rejects it against "str".
# The entire rule is suppressed — not just parameter a.
# → rule does NOT fire.
result = Foo.f(42, 42)
