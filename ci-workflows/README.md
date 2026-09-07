# CI workflow files (staged here because the initial push token lacked `workflow` scope)

To enable GitHub Actions, move these into `.github/workflows/` and push:

```bash
mkdir -p .github/workflows
git mv ci-workflows/reproduce.yml .github/workflows/reproduce.yml
git mv ci-workflows/testbed.yml  .github/workflows/testbed.yml
git rm ci-workflows/README.md
git commit -m "Enable CI workflows"
git push          # if rejected: gh auth refresh -h github.com -s workflow && git push
```

* **reproduce.yml** — ubuntu-latest, Python 3.10 + paper pins: full pipeline for
  both config sets + pytest, comparison tables in the run summary, artifacts.
* **testbed.yml** — ubuntu-22.04: best-effort real Mininet + OVS + Ryu + Scapy +
  hping3 run of `scripts/run_testbed.sh`.
