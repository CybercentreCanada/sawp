# [Français](CONTRIBUTING.fr.md)

# Contributing

This project is actively maintained and accepting open source contributions.

Please discuss any planned changes by creating an issue or contacting us
directly to make sure no one else is working on the same feature and to see
if the proposed change aligns with our vision for the library.

A certain code of conduct is expected of all contributors and please refer to
the [Rust code of conduct](https://www.rust-lang.org/policies/code-of-conduct)
as an example.

By contributing to this project you acknowledge that all contributions will be
made under the licensing agreement located in the LICENSE file.

## Guidelines

The [Rust API Guidelines Checklist](https://rust-lang.github.io/api-guidelines/checklist.html)
provides a good overview of best practices and naming conventions.

### Commit Messages

- Commits should be limited to one logical feature or bugfix.
- Code should not be moved and changed in the same commit.
- Please keep a clean, descriptive and concise git history. Squash when needed.
- Include compile errors or steps to reproduce when applicable.
- Commits should have a 50 character max title line with the module/area and a
  short description. The body can then describe the commit in detail.

```
module: short description

Describe the commit here.
```

### Pull Requests

- Each pull request should be limited to one logical feature or bugfix in most cases.
- Please use the [fork and pull](https://docs.github.com/en/free-pro-team@latest/github/collaborating-with-issues-and-pull-requests/about-collaborative-development-models)
  model to open pull requests on github.
- Keep your branch up to date with main by using `git rebase -i main` and to avoid
  merge commits. Force pushing these changes to your fork's branch is fine.
- A pull request may be updated with changes once open.
- We will either "rebase and merge" or "squash and merge" your pull request once accepted.

A descriptive pull request will make it easier to review:

- fully describe the feature or bugfix
- include sample usage, input or output when applicable
- include links to relevant issues, pull requests and external documentation such as
  the protocol specifications referenced

### Coding Style

Use `cargo fmt --all` for code formatting.

General style guidelines that should be followed unless there is reason to do otherwise:

- Lines should not exceed a width of 100 characters, including comments.
- Variable names should be descriptive.

Comments on the previous line are preferred over trailing comments:

_Preferred_
```rust
// Comment for value.
let value = 10;
```

_Avoid_
```rust
let value = 10; // Comment for value.
```

### Testing & QA

We are committed to upholding a certain level of code quality. Please include unit tests to
cover as much of the feature or bugfix as possible.