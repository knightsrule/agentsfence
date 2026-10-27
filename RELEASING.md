# Releasing AgentsFence to PyPI

A push to `main` runs GitHub Actions CI, including the Python, Windows and real-Hermes jobs. After all of them pass, the release job checks the package version on PyPI. An already published version needs no release. An unpublished version gets an annotated `v<version>` tag and starts [`.github/workflows/publish-pypi.yml`](.github/workflows/publish-pypi.yml). That workflow tests and builds the wheel and source distribution, then publishes them to the public `agentsfence` project through GitHub OIDC. Published distributions contain the plugin code.

CI and publication run on GitHub's runners. No personal access tokens, PyPI API tokens or cross-repository triggers are involved.

## One-time PyPI setup

For the first release, sign in to [PyPI's publishing settings](https://pypi.org/manage/account/publishing/) with a 2FA-enabled account. If `agentsfence` has not yet been published there, add a **pending GitHub publisher** with these exact values:

| Field | Value |
| --- | --- |
| PyPI project name | `agentsfence` |
| GitHub owner | `knightsrule` |
| GitHub repository | `agentsfence` |
| Workflow filename | `publish-pypi.yml` |
| Environment name | `pypi` |

The workflow uses GitHub OIDC; do not create or store a PyPI API token. A pending publisher does not reserve the project name. Create it shortly before the first release.

The `pypi` GitHub environment is configured to admit only `v*` tags. Keep this rule in place. Restrict who can create or update release tags in the repository. The workflow also requires a tag and checks that the tagged commit is on `main`; it does not grant publish credentials to its test/build job. Only CI's release job has `contents: write` and `actions: write`, to create the tag and dispatch publication. Repository or organization rules must allow these job permissions and the bot to create release tags.

GitHub does not start a push workflow for a tag created with `GITHUB_TOKEN`. CI therefore explicitly dispatches the publishing workflow at the tag using that same token. Keep `workflow_dispatch` enabled in `publish-pypi.yml`; a manual dispatch from a branch is rejected.

## Each release

1. Update the version in `pyproject.toml`, `agentsfence/__init__.py`, and `plugin.yaml`, and add a dated `CHANGELOG.md` entry. Pushing an unpublished version to `main` is the release decision, including alpha versions.
   For 0.3.0a1 and later, or any beta, release candidate or final version, then run `scripts/beta_validate.py` with a real compiler from the clean candidate commit and commit `release-evidence/<version>/` (see [BETA_GATE.md](BETA_GATE.md), "Final recorded validation"). The release job refuses such a version without a complete PASS record, or if code changed after it was recorded, and **Publish to PyPI** runs the same check (`prepare_release.py --check-evidence`), so a manually pushed tag or dispatch cannot skip it. The 0.2 alpha series, including 0.2.0a8, does not require this recorded gate; ordinary CI remains required. Compiler reliability and native Desktop approval validation remain prerequisites for beta.
2. Run `.venv/bin/ruff check .`, `.venv/bin/mypy`, `.venv/bin/pytest`, and `.venv/bin/agentsfence --help` locally. Push the commit to `main` and wait for CI to pass. Do not tag a commit that has not reached `main`.
3. CI automatically creates the normalized tag (for example, `v0.2.0a5`) and starts **Publish to PyPI**. It skips a superseded `main` commit, checks all three version declarations, and stops on a PyPI outage or an incomplete/yanked release. An existing unpublished tag can be retried only at its original commit.
4. Confirm that the **Publish to PyPI** workflow succeeds and that the new release appears at <https://pypi.org/project/agentsfence/>. Install it into a clean Hermes environment and verify `agentsfence protect --profile default` and `agentsfence doctor` before changing the website's install instructions.

When validating a new Hermes release, add it to the `hermes` job matrix in `.github/workflows/ci.yml` and to "Supported Hermes versions" in `HERMES_API.md` (the website links to this repository contract).

Do not move a published tag or reuse a version. If a release fails after publication, fix the issue and publish a new version.

## Retrying and the website

If CI or its release job fails, fix the cause and rerun the failed jobs. If the tag already exists and publication failed, rerun **Publish to PyPI**, or run `gh workflow run publish-pypi.yml --ref v0.2.0a5` using the actual release tag. Inspect any partial PyPI upload before retrying; published filenames cannot be replaced. A manual annotated tag on a tested `main` commit still starts the same publishing workflow.

The website repository deploys independently through Vercel's GitHub integration. Its build checks every pinned `agentsfence==...` install command against public PyPI and requires an unyanked wheel and source distribution. Publish and verify the plugin first, then merge/push the website's updated pins to its own `main`. There is no cross-repo credential or trigger. See that repo's `RELEASING.md` for Vercel setup and deployment recovery.
