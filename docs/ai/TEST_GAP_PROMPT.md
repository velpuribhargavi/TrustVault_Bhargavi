# Reusable prompt: find what the tests do not prove

Used together with `python tools/mutation_check.py`. Paste the tool's output
and the relevant test file after it.

---

Here is the output of TrustVault's mutation checker (it removes one tagged
authorisation check at a time and runs the test suite) and the test file for
that area.

1. For every SURVIVED mutant, write the smallest pytest test (using the `world`
   fixture in tests/conftest.py) that would fail with that check removed and
   pass with it present. Do not change application code.
2. For every KILLED mutant, look at *which* test killed it. If it was killed by
   a crash (500) rather than by an assertion about access, say so - that test
   is not really proving the security property; propose a better one.
3. List security behaviours in THREATS.md that have no tagged check at all
   (e.g. something enforced only by SQL or by a database constraint) and say how
   to tag or test them.
