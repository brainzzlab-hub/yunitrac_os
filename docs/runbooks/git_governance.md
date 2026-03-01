# Git Governance Runbook (to apply when moving to GitHub)

## Repository visibility
- Create a **private** GitHub repository.
- Invite-only access; default role for collaborators: **Read**.
- Only HL (approvers) get **Admin/Maintain**.

## Branch protection (main)
1. Settings → Branches → Add rule for `main`.
2. Require pull requests before merging.
3. Require at least **1 approval**.
4. Require **CODEOWNERS** review.
5. Require status checks to pass (CI workflow).
6. Require branches to be up to date before merging.
7. Block force pushes.
8. Block branch deletions.
9. Restrict who can push: only HL/Release admins.

## Checklist after enabling
- Direct pushes to `main` are blocked.
- PR merge is blocked until CI + approvals (incl. CODEOWNERS) succeed.
- Protected branch cannot be force-pushed or deleted.
- Only designated admins can modify protection rules.
