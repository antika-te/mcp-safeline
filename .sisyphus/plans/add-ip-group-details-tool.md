# Add IP Group Details Tool

## TL;DR
> Add or confirm a `get_ip_group_details` MCP tool in the local SafeLine server so callers can fetch full IP group membership details by group ID, then verify it automatically with focused regression coverage.
>
> Deliverables:
> - One authoritative `get_ip_group_details` tool contract in `mcp_safeline/server.py`
> - One authoritative dispatch route for the tool
> - Automated verification for discovery, dispatch, and error handling
>
> Estimated Effort: Short
> Parallel Execution: NO - sequential due to baseline mismatch risk
> Critical Path: Baseline validation -> contract lock -> wiring -> regression verification -> final QA

---

## Context

### Original Request
Add `get_ip_group_details` support to the SafeLine MCP server at `/Users/wendell/py_projects/mcp-safeline/mcp_safeline/server.py` so IP group member details can be retrieved.

### Interview Summary
**Key Discussions**:
- Scope is limited to the local MCP implementation for this one tool.
- Target file path is `/Users/wendell/py_projects/mcp-safeline/mcp_safeline/server.py`.
- Test strategy is `Tests after`.

**Research Findings**:
- Existing SafeLine responses for IP group details include fields like `id`, `name`, `comment`, `original`, and `cidrs`.
- The current working tree appears to already contain `get_ip_group_details`, so the first implementation step must reconcile whether the plan targets this tree or another snapshot.

### Metis Review
**Identified Gaps** (addressed):
- Baseline mismatch: plan explicitly starts by verifying whether the tool is already present in the target branch.
- Contract ambiguity: plan locks input and output behavior before implementation work.
- Missing verification: plan includes narrow automated checks for happy path and failure path.

---

## Work Objectives

### Core Objective
Ensure the SafeLine MCP exposes a single authoritative `get_ip_group_details` capability that returns detailed IP group membership information without changing unrelated server behavior.

### Concrete Deliverables
- `mcp_safeline/server.py` contains exactly one `get_ip_group_details` tool declaration.
- `mcp_safeline/server.py` contains exactly one authoritative dispatch path for `get_ip_group_details`.
- Automated verification covers tool discovery, dispatch shape, passthrough response handling, and one error path.

### Definition of Done
- [ ] The target baseline is reconciled and the plan records whether the tool was missing or already present.
- [ ] Automated verification command exits successfully.
- [ ] No unrelated SafeLine MCP tools are changed.

### Must Have
- Minimal scope limited to this tool and its verification.
- No duplicate tool definitions.
- Clear executable verification steps.

### Must NOT Have (Guardrails)
- No refactor of adjacent IP group tools.
- No change to global error formatting unless required by the tool contract.
- No normalization of upstream payload unless explicitly chosen during implementation.
- No unrelated README, config, or transport changes.

---

## Verification Strategy

> ZERO HUMAN INTERVENTION - all verification must be executable by the agent.

### Test Decision
- Infrastructure exists: NO dedicated test harness confirmed
- Automated tests: Tests-after
- Framework: Prefer Python stdlib `unittest` unless the executor deliberately adds a minimal dependency
- If not using stdlib, the executor must explicitly justify the added dependency before widening scope
- Tool input default: require `id` only
- Response handling default: pass upstream JSON through unchanged

### QA Policy
Every implementation task must include agent-executed QA scenarios.
Evidence saved to `.sisyphus/evidence/task-{N}-{scenario-slug}.{ext}`.

- Library/Module: Use Bash with `uv run python -m unittest ...` or equivalent
- Syntax/Import: Use Bash with `uv run python -m compileall mcp_safeline`
- API call shape: Use mocks or isolated tests rather than live SafeLine mutation for regression coverage

---

## Execution Strategy

### Parallel Execution Waves

> This work stays intentionally serialized because the first task may collapse the implementation branch into a no-op if the current working tree is already authoritative.

Wave 1 (Start Immediately - baseline):
├── Task 1: Validate target baseline and reconcile current tree [quick]
└── Task 2: Lock contract and non-goals after baseline confirmation [quick]

Wave 2 (After Wave 1 - implementation):
├── Task 3: Implement or confirm minimal server wiring [quick]
└── Task 4: Add focused automated verification [unspecified-low]

Wave 3 (After Wave 2 - finalization):
└── Task 5: Run QA and commit atomically if changes exist [quick]

Wave FINAL (After all tasks):
├── Task F1: Plan compliance audit [oracle]
├── Task F2: Code quality review [unspecified-high]
├── Task F3: Real QA against task scenarios [unspecified-high]
└── Task F4: Scope fidelity check [deep]

Critical Path: Task 1 -> Task 2 -> Task 3 -> Task 4 -> Task 5 -> F1-F4
Parallel Speedup: Minimal by design
Max Concurrent: 2

### Dependency Matrix
- **1**: None -> 2, 3
- **2**: 1 -> 3, 4
- **3**: 1, 2 -> 4, 5
- **4**: 2, 3 -> 5
- **5**: 4 -> F1-F4

### Agent Dispatch Summary
- **Wave 1**: 2 tasks - T1 `quick`, T2 `quick`
- **Wave 2**: 2 tasks - T3 `quick`, T4 `unspecified-low`
- **Wave 3**: 1 task - T5 `quick`
- **FINAL**: 4 tasks - F1 `oracle`, F2 `unspecified-high`, F3 `unspecified-high`, F4 `deep`

---

## TODOs

- [ ] 1. Validate target baseline and reconcile current tree

  **What to do**:
  - Confirm whether `/Users/wendell/py_projects/mcp-safeline/mcp_safeline/server.py` in the current working tree is the actual target baseline.
  - Compare the draft assumption with the current file state, because the working tree appears to already contain `get_ip_group_details`.
  - Record one explicit outcome for the executor: `already present in target tree` or `missing on target branch`.

  **Must NOT do**:
  - Do not start editing implementation before the baseline is reconciled.
  - Do not assume the draft is more authoritative than the current working tree.

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: bounded inspection and decision capture in one file.
  - **Skills**: []
  - **Skills Evaluated but Omitted**:
    - `git-master`: no git history surgery needed for this decision.
    - `playwright`: no browser work.

  **Parallelization**:
  - **Can Run In Parallel**: NO
  - **Parallel Group**: Wave 1
  - **Blocks**: 2, 3
  - **Blocked By**: None

  **References**:
  - `/Users/wendell/py_projects/mcp-safeline/mcp_safeline/server.py` - authoritative implementation file to inspect for existing tool wiring.
  - `.sisyphus/drafts/add-ip-group-details-tool.md` - planning draft that currently assumes the tool needs to be added.

  **Acceptance Criteria**:
  - [ ] The executor records whether `get_ip_group_details` already exists in the target baseline.
  - [ ] The plan or execution notes state one concrete outcome: `already present` or `missing`.

  **QA Scenarios**:
  ```
  Scenario: Confirm current tree contains or lacks the tool
    Tool: Bash
    Preconditions: Working tree available at /Users/wendell/py_projects/mcp-safeline
    Steps:
      1. Run `python - <<'PY'
from pathlib import Path
text = Path('mcp_safeline/server.py').read_text()
print('get_ip_group_details' in text)
PY`
      2. Record whether output is `True` or `False`.
      3. If `True`, locate both the tool declaration and dispatch branch before proceeding.
    Expected Result: A binary baseline decision is captured before any implementation edits.
    Failure Indicators: Implementation starts without confirming whether the tool already exists.
    Evidence: .sisyphus/evidence/task-1-baseline-check.txt

  Scenario: Prevent duplicate implementation path
    Tool: Bash
    Preconditions: Same repository state
    Steps:
      1. Run `python - <<'PY'
from pathlib import Path
text = Path('mcp_safeline/server.py').read_text()
print(text.count('name="get_ip_group_details"'))
PY`
      2. Assert the count is known before any edit plan is executed.
    Expected Result: The executor knows whether duplication risk exists.
    Evidence: .sisyphus/evidence/task-1-duplication-risk.txt
  ```

  **Commit**: NO

- [ ] 2. Confirm locked contract and non-goals

  **What to do**:
  - Confirm the locked default contract: accept `id` only.
  - Confirm the locked default response behavior: pass upstream JSON through unchanged.
  - Lock non-goals: no unrelated MCP refactors, no README/config churn, no error wrapper rewrite.
  - Freeze the verification command and test harness choice before code work starts.

  **Must NOT do**:
  - Do not widen the contract beyond `id`-only input unless the user later asks for alias support.
  - Do not widen the change into general IP group cleanup.

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: narrow contract-setting task with no implementation complexity.
  - **Skills**: []
  - **Skills Evaluated but Omitted**:
    - `git-master`: not a git task.
    - `playwright`: no browser surface.

  **Parallelization**:
  - **Can Run In Parallel**: NO
  - **Parallel Group**: Wave 1
  - **Blocks**: 3, 4
  - **Blocked By**: 1

  **References**:
  - `/Users/wendell/py_projects/mcp-safeline/mcp_safeline/server.py` - current naming and dispatch conventions to match.
  - `.sisyphus/drafts/add-ip-group-details-tool.md` - confirmed scope and test strategy.

  **Acceptance Criteria**:
  - [ ] Input contract is explicitly written as `id` only.
  - [ ] Output contract is explicitly written as passthrough JSON.
  - [ ] Verification command is explicitly chosen as stdlib unittest unless justified otherwise.

  **QA Scenarios**:
  ```
  Scenario: Contract is explicit before coding
    Tool: Bash
    Preconditions: Planning notes updated
    Steps:
      1. Read the execution notes or plan section for Task 2.
      2. Assert it states the exact accepted input key(s) and exact response handling mode.
      3. Assert it names one exact verification command.
    Expected Result: No ambiguity remains for the executor.
    Failure Indicators: Missing decision on aliasing, response shape, or test command.
    Evidence: .sisyphus/evidence/task-2-contract-check.txt

  Scenario: Scope guardrails are explicit
    Tool: Bash
    Preconditions: Same planning notes
    Steps:
      1. Confirm non-goals explicitly say no unrelated IP group refactor and no error-wrapper rewrite.
      2. Confirm no additional unrelated modules are listed in scope.
    Expected Result: Scope creep is locked down.
    Evidence: .sisyphus/evidence/task-2-guardrails.txt
  ```

  **Commit**: NO

- [ ] 3. Implement or confirm minimal server wiring

  **What to do**:
  - If the target branch lacks the tool, add exactly one `types.Tool(...)` entry in `list_tools()`.
  - Add exactly one `_dispatch()` branch that routes `get_ip_group_details` to the agreed SafeLine endpoint.
  - If the current tree is already authoritative, mark this task as no-op and preserve the existing implementation without duplication.

  **Must NOT do**:
  - Do not define the tool twice.
  - Do not refactor neighboring IP group tools.
  - Do not change transport/auth/client behavior.

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: single-file, low-complexity MCP wiring.
  - **Skills**: []
  - **Skills Evaluated but Omitted**:
    - `git-master`: not needed during code edit itself.
    - `playwright`: no browser surface.

  **Parallelization**:
  - **Can Run In Parallel**: NO
  - **Parallel Group**: Wave 2
  - **Blocks**: 4, 5
  - **Blocked By**: 1, 2

  **References**:
  - `/Users/wendell/py_projects/mcp-safeline/mcp_safeline/server.py` - add or confirm tool definition and dispatch branch following existing conventions.

  **Acceptance Criteria**:
  - [ ] `list_tools()` exposes exactly one `get_ip_group_details` definition.
  - [ ] `_dispatch()` exposes exactly one `get_ip_group_details` branch.
  - [ ] The dispatch calls the agreed SafeLine endpoint with the agreed request body.

  **QA Scenarios**:
  ```
  Scenario: Tool is discoverable exactly once
    Tool: Bash
    Preconditions: Implementation complete
    Steps:
      1. Run `python - <<'PY'
from pathlib import Path
text = Path('mcp_safeline/server.py').read_text()
print(text.count('name="get_ip_group_details"'))
PY`
      2. Assert output is `1`.
      3. Run a second search for `elif name == "get_ip_group_details"` and assert output is `1`.
    Expected Result: One tool declaration and one dispatch branch exist.
    Failure Indicators: Count is `0` or greater than `1`.
    Evidence: .sisyphus/evidence/task-3-single-definition.txt

  Scenario: Dispatch shape matches contract
    Tool: Bash
    Preconditions: Implementation complete
    Steps:
      1. Inspect the `_dispatch()` branch for `get_ip_group_details`.
      2. Assert the request path and body match the contract from Task 2.
    Expected Result: Dispatch code matches the planned endpoint and payload.
    Evidence: .sisyphus/evidence/task-3-dispatch-shape.txt
  ```

  **Commit**: NO

- [ ] 4. Add focused automated verification

  **What to do**:
  - Add narrow regression coverage for tool discovery and dispatch behavior.
  - Verify the happy path using a concrete example such as `{"id": 42}`.
  - Verify one failure path such as missing `id`, invalid `id`, or upstream HTTP error wrapping, depending on the contract chosen in Task 2.

  **Must NOT do**:
  - Do not introduce broad integration coverage unrelated to this tool.
  - Do not require live SafeLine state mutation for regression tests when mocks are sufficient.

  **Recommended Agent Profile**:
  - **Category**: `unspecified-low`
    - Reason: small but slightly more open-ended because the repo has no dedicated test harness yet.
  - **Skills**: []
  - **Skills Evaluated but Omitted**:
    - `playwright`: not a UI/browser task.
    - `git-master`: not a git task.

  **Parallelization**:
  - **Can Run In Parallel**: NO
  - **Parallel Group**: Wave 2
  - **Blocks**: 5
  - **Blocked By**: 2, 3

  **References**:
  - `/Users/wendell/py_projects/mcp-safeline/mcp_safeline/server.py` - functions and branches under test.

  **Acceptance Criteria**:
  - [ ] Happy path test verifies dispatch with `{"id": 42}`.
  - [ ] Happy path test verifies response payload is returned unchanged if passthrough is chosen.
  - [ ] Failure path test verifies agreed missing-input or upstream-error behavior.
  - [ ] Exact verification command is executable.

  **QA Scenarios**:
  ```
  Scenario: Happy path regression passes
    Tool: Bash
    Preconditions: Focused tests added
    Steps:
      1. Run `uv run python -m unittest discover -s tests -p "test_*.py"`.
      2. Assert the suite includes coverage for `get_ip_group_details` with `{"id": 42}`.
      3. Assert exit code is `0`.
    Expected Result: Regression coverage passes without live API dependency.
    Failure Indicators: Non-zero exit code or missing test coverage for the tool.
    Evidence: .sisyphus/evidence/task-4-happy-path.txt

  Scenario: Failure path regression passes
    Tool: Bash
    Preconditions: Same test suite
    Steps:
      1. Run the same unittest command.
      2. Confirm one test covers a missing-input or HTTP error branch.
      3. Assert exit code is `0` and the failure behavior matches the locked contract.
    Expected Result: Error handling remains predictable and verified.
    Evidence: .sisyphus/evidence/task-4-failure-path.txt
  ```

  **Commit**: NO

- [ ] 5. Run QA and commit atomically if changes exist

  **What to do**:
  - Execute the agreed regression test command.
  - Run a syntax/import verification step for the package.
  - Create one atomic commit only if implementation or verification files changed.

  **Must NOT do**:
  - Do not create multiple tiny commits for one scoped change.
  - Do not commit unrelated working tree changes.

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: final bounded QA and commit preparation.
  - **Skills**: [`git-master`]
    - `git-master`: safe staging/commit hygiene if a commit is requested during execution.
  - **Skills Evaluated but Omitted**:
    - `playwright`: no browser QA.

  **Parallelization**:
  - **Can Run In Parallel**: NO
  - **Parallel Group**: Wave 3
  - **Blocks**: F1, F2, F3, F4
  - **Blocked By**: 3, 4

  **References**:
  - `/Users/wendell/py_projects/mcp-safeline/mcp_safeline/server.py` - target module for compile and review.

  **Acceptance Criteria**:
  - [ ] `uv run python -m unittest discover -s tests -p "test_*.py"` exits `0`.
  - [ ] `uv run python -m compileall mcp_safeline` exits `0`.
  - [ ] One atomic commit is prepared only if scoped changes exist.

  **QA Scenarios**:
  ```
  Scenario: Final regression and syntax checks pass
    Tool: Bash
    Preconditions: Implementation and tests complete
    Steps:
      1. Run `uv run python -m unittest discover -s tests -p "test_*.py"`.
      2. Run `uv run python -m compileall mcp_safeline`.
      3. Assert both exit codes are `0`.
    Expected Result: Tool wiring and package syntax are verified together.
    Failure Indicators: Any command exits non-zero.
    Evidence: .sisyphus/evidence/task-5-final-qa.txt

  Scenario: Commit scope stays clean
    Tool: Bash
    Preconditions: Changes staged for commit if needed
    Steps:
      1. Run `git diff --name-only --cached`.
      2. Assert staged files are limited to the scoped implementation and verification files.
    Expected Result: Atomic commit scope remains tight.
    Evidence: .sisyphus/evidence/task-5-commit-scope.txt
  ```

  **Commit**: YES
  - Message: `Add MCP IP group details tool`
  - Files: `mcp_safeline/server.py`, test files if added
  - Pre-commit: `uv run python -m unittest discover -s tests -p "test_*.py"`

---

## Final Verification Wave

> 4 review agents run in parallel after implementation. Any rejection loops back to fixes before completion.

- [ ] F1. Plan Compliance Audit - `oracle`
  Verify the final implementation matches this plan: one tool declaration, one dispatch path, no unrelated MCP edits, and evidence files exist.

- [ ] F2. Code Quality Review - `unspecified-high`
  Run syntax/import verification and test command. Check for duplicate tool definitions, broken typing, and unnecessary scope expansion.

- [ ] F3. Real QA - `unspecified-high`
  Execute every task QA scenario and save evidence under `.sisyphus/evidence/final-qa/`.

- [ ] F4. Scope Fidelity Check - `deep`
  Compare actual changes against the plan and reject any unrelated server modifications.

---

## Commit Strategy

- Use one atomic commit only if code or tests changed.
- If the current working tree already contains the complete tool and only verification is added, commit verification only.
- Recommended message if implementation is needed: `Add MCP IP group details tool`
- Recommended message if only regression coverage is added: `Add regression coverage for IP group details tool`

---

## Success Criteria

### Verification Commands
```bash
uv run python -m unittest discover -s tests -p "test_*.py"
uv run python -m compileall mcp_safeline
```

### Final Checklist
- [ ] Baseline mismatch resolved before implementation edits
- [ ] Exactly one `get_ip_group_details` tool path exists
- [ ] Automated verification covers happy and failure paths
- [ ] No unrelated MCP functionality changed
