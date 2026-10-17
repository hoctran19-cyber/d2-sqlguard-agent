# Contributing

1. Sync the shared default branch and create a focused branch, for example `feat/sql-policy`.
2. Keep changes within the owning module; coordinate interface changes with affected owners before implementation.
3. Use clear, imperative commit messages. Do not commit `.env` files, credentials, private data, caches, or generated reports.
4. Before opening a pull request, run:

   ```bash
   pytest -q
   ruff check .
   ruff format --check .
   ```

5. Open a pull request against the agreed default branch. Describe behavior, security implications, tests, limitations, and any interface changes.
6. Request review from the module owner and at least one affected collaborator. Resolve comments with follow-up commits and rerun relevant checks.
7. Keep the branch current with the default branch. Resolve conflicts by understanding both changes, preserving intended behavior, and rerunning tests; do not discard another contributor's work.
8. Merge only after required reviews and CI checks pass, using the repository's configured merge policy.

The commands above are guidance; actual branch protections and merge permissions are controlled by repository administrators.
