# CONTRIBUTING

## Commit Messages
- Commits should have a 50 character max title line with the module/area and a
  short description. The body can then describe the commit in detail.
```
module: short description

Describe the commit here.
```

## Pull Requests
- Default is to `squash` merges to keep a clean git history.
- PRs should be logically separated so that your squashed commit resolves one single issue.
- Try to remove the `Approved by:` lines when you are merging as they are noisy.
- Updating PRs is fine using the rebase and force push workflow:
```
# update master
git fetch origin master:master
# start from your branch
git checkout ticketnum-my-branch-short-name
# get the latest updates from master, resolve merge conflicts,
# or modify your commits.
git rebase -i master
# when done, force push your working branch
git push -f origin ticketnum-my-branch-short-name
```

## Coding Style
- Use `cargo fmt --all` for code formatting.
- Use standard rust naming conventions as suggested by the compiler.

