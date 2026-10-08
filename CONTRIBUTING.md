# Contributing to trailhunt

Thanks for helping! Bug reports, new detections, rule tuning and engine
improvements are all welcome.

## Development setup

```bash
git clone https://github.com/Opsbreak/trailhunt && cd trailhunt
python -m venv .venv
. .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Before opening a pull request, run what CI runs:

```bash
ruff check .
ruff format --check .
pytest
trailhunt rules test
```

## Contributing a detection rule

1. **Pick the rule type** that matches the behaviour: `match` for a single
   telling event, `threshold` for volume or variety in a window, `sequence` for
   ordered steps (or something that did *not* happen), `new_value` for
   first-seen behaviour. See the "Rule language" section of the README.
2. **Add it** to the right file in `src/trailhunt/rules/builtin/`
   (`identity`, `defense-evasion`, `discovery`, `exfiltration`, `execution`,
   `anomaly`) or a new themed file. Ids are lowercase, unique and descriptive
   (`iam-access-key-for-other-user`).
3. **Fill in the metadata:** `title`, `severity`, `description` (what and why),
   `attack` (MITRE ATT&CK technique ids), and `falsepositives` - the benign
   situations that will trigger it. Built-in rules must have all of these
   (the test suite enforces it).
4. **Write tests in the rule** under `tests:` with at least one `positive` and
   one `negative` case. Good negatives are the near misses: the same API with
   a benign parameter, the window boundary, the wrong order, a different join
   key, a failed (`errorCode`) call. Use the helpers (`_at`, `_repeat`,
   `_interval`, `_cycle`, `_user`, `_role`) to keep cases short.
5. **Check precision against the synthetic dataset.** The test suite asserts
   that the benign-only generated dataset produces **zero** findings and that
   the sample attack produces an exact set of rule ids. If your rule fires on
   benign data, tighten it (or, if the generator is unrealistic, improve the
   generator). If it should fire on the embedded attack, add its id to
   `EXPECTED_ATTACK_RULES` in `tests/test_dataset.py`; if the attack does not
   exercise it yet, you may extend the attack scenario in
   `examples/generate_dataset.py` and regenerate the sample:

   ```bash
   python examples/generate_dataset.py --force
   ```

   The generator is deterministic; commit the regenerated `examples/sample-logs`
   (keep it under 2 MB) and update the README output if it changed.
6. Run `trailhunt rules validate` and `trailhunt rules test -v`.

Rule quality guidelines:

* Prefer `eventName` constraints at the top level of `match` - the engine
  indexes rules by event name, so such rules cost nothing for unrelated events.
* Filter out failed calls (`errorCode: {exists: false}`) unless the attempt
  itself is the signal.
* Exclude AWS service activity (`actor_type: {not_in: [AWSService]}`) and
  console fan-out (`ua_family: {not_in: [console, aws-internal]}`) where it
  would add noise.
* Use `suppress` for single-event rules that can fire on every call of a session.
* Quote YAML strings that look like booleans (`"No"`, `"Yes"`, `"off"`).

## Engine changes

* Keep the hot path allocation-light; measure with the sample dataset
  (`trailhunt hunt examples/sample-logs` prints events/s) before and after.
* Detectors must work in **event time** and stay bounded in memory.
* Add tests for window edges, ordering and state expiry.

## Pull requests

* One logical change per PR, with tests.
* Add an entry under "Unreleased" in `CHANGELOG.md`.
* By contributing you agree that your contribution is licensed under the
  project's MIT license.

## Reporting security issues

Please see [SECURITY.md](SECURITY.md) - do not open public issues for vulnerabilities.
