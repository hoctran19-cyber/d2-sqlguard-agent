"""Naive agent for the prompt-injection seminar demo: a DELIBERATELY UNSAFE configuration.

Nothing here is part of SQLGuard's runtime. The naive agent puts permissions in the prompt only,
lets the model call ``execute_sql`` over several turns and read the rows, and lets the model write
the answer. It exists to show, next to SQLGuard and with the same payload, what injection looks
like when those layers are missing (``docs/threat-model/NAIVE_AGENT_DEMO.md``).

It is off by default and only runs on an Attack Lab copy (``naive_guard``). ``sqlguard.agent``,
``sqlguard.security`` and ``evaluation`` must never import this package.
"""
