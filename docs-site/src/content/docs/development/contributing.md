---
title: Contributing
description: How to contribute to the Falcon MCP Server project.
---

Thank you for your interest in contributing to the Falcon MCP Server! This guide covers the contribution workflow, commit standards, and how to get help.

## How to Contribute

1. **Find an issue** in the [GitHub Issues](https://github.com/CrowdStrike/falcon-mcp/issues) section, or identify a feature to add.

2. **Fork the repository** to your GitHub account.

3. **Clone your fork:**

   ```bash
   git clone https://github.com/your-username/falcon-mcp.git
   cd falcon-mcp
   ```

4. **Create a branch:**

   ```bash
   git checkout -b my-feature-branch
   ```

5. **Install dependencies:**

   ```bash
   uv sync --all-extras
   source .venv/bin/activate
   ```

6. **Make your changes** following the coding standards below.

7. **Run linting:**

   ```bash title="Import sorting"
   uv run ruff check . --select I
   ```

   ```bash title="General linting"
   uv run ruff check .
   ```

   ```bash title="Auto-fix issues"
   uv run ruff check --fix .
   ```

8. **Commit** using Conventional Commits (see below).

9. **Push and open a pull request** to the upstream repository.

## Conventional Commits

This project uses [Conventional Commits](https://www.conventionalcommits.org/) for automated releases and semantic versioning.

**Format:** `<type>[optional scope]: <description>`

**Common types:**

- `feat:` — new feature (triggers minor version bump)
- `fix:` — bug fix (triggers patch version bump)
- `docs:` — documentation changes
- `refactor:` — code changes that neither fix bugs nor add features
- `test:` — adding or correcting tests
- `chore:` — build process or tooling changes

**Examples with scopes (preferred):**

```bash frame="none"
git commit -m "feat(modules/cloud): add list kubernetes clusters tool"
git commit -m "fix(modules/detections): resolve authentication error"
git commit -m "docs(contributing): update conventional commits guidance"
git commit -m "feat(resources): add FQL guide for hosts module"
```

**Breaking changes:**

```bash
git commit -m "feat!: change API authentication method"
# or include BREAKING CHANGE: in the footer
```

## Staying in Sync

Rebase frequently to keep your fork current with upstream:

```bash
git fetch upstream
git rebase upstream/main
```

See [GitHub's fork syncing docs](https://docs.github.com/en/github/collaborating-with-issues-and-pull-requests/syncing-a-fork) for details.

## Running Tests

Unit tests:

```bash
uv run pytest
```

Integration tests (requires API credentials):

```bash
uv run pytest --run-integration tests/integration/
```

E2E tests (requires API credentials + OpenAI key):

```bash
uv run pytest --run-e2e tests/e2e/
```

## Getting Help

- Open an issue in the [project repository](https://github.com/CrowdStrike/falcon-mcp/issues)
- For broader CrowdStrike community questions, [open a community discussion](https://github.com/CrowdStrike/community/discussions/new)
