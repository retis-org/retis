# Contribution guidelines

Thank you for investing your time and considering contributing to Retis! :tada:

This guide documents the process to get changes merged into this project, what
one should expect, as well as prerequisites for pull-requests and patches to be
considered acceptable.

### Table of contents

* [Reporting bugs](#reporting-bugs)
* [Suggesting new features](#suggesting-new-features)
* [Code contribution](#code-contribution)

## Reporting bugs

Following the guidelines will help the community understand bug reports, which
in turns will help in reproducing, triaging and fixing those bugs.

### Before submitting the report

1. Check for similar opened or closed issues. If a similar issue is still
   opened, please add a comment there.
1. Check the version used when the bug was triggered. If it was not the latest,
   please reproduce with it.

### Submitting a good bug report

1. Use a clear, concise and descriptive title.
1. Describe how to reproduce the bug, in clear exact steps, with examples. The
   community should not have to guess extra steps, configuration, prerequisites
   and spend lot of time gathering this information to work on fixing a bug.
1. How reliable are those steps to reproduce the issue?
1. Describe the outcome of those steps.
1. Then describe what would have been expected and why.
1. If it is performances related, include numbers.

### Following-up on the report

* It's OK to ping *once* or *twice*.
* But give time to the community to reproduce and come up with a solution.
* Also note we all have limited time and prioritize things.

## Suggesting new features

Features requirement vary depending on users, use cases, priorities, etc. But
expressing an interest is valuable as it can help prioritizing things and
shaping the actual behavior.

### Before suggesting a new feature

1. Check the feature isn't already available. See the tool help.
1. Check it is not already being planned by looking at the different
   [milestones](https://github.com/retis-org/retis/milestones) and
   [issues](https://github.com/retis-org/retis/issues). If a matching issue is
   found, please comment on it to express an interest and make suggestions.

### Adding an issue to request a new feature

1. Use a clear, concise and descriptive title.
1. Describe the environment on which the feature would be used and provide
   value.
1. Provide a detailed explanation of what you'd like to be implemented, the
   expected output and behavior.
1. If applicable, explain what the current behavior is lacking and how different
   you'd like it to be.
1. Understand we have limited time and do prioritize things. In this regard,
   external contributions for new features are highly recommended and can have a
   great impact in choosing the direction of the project.

## Code contribution

Looking for topics to work on? Please have a look at issues triaged as
[good first issues](https://github.com/retis-org/retis/issues?q=is%3Aissue+is%3Aopen+label%3A"good+first+issue")
and/or [help wanted](https://github.com/retis-org/retis/issues?q=is%3Aissue+is%3Aopen+label%3A"help+wanted").

### Guidelines

1. Follow the [coding style](#coding-style).
1. Document functions, structures (including members), enums, ..., and the code
   itself. You can look at the existing code for understanding what level of
   documentation we expect.
1. Add unit tests.
1. Base new work on top of the `main` branch.

### Coding style

We strictly follow the Rust coding style as enforced by `rustfmt` and have a
strong preference for the
[Linux kernel](https://www.kernel.org/doc/html/latest/process/coding-style.html)
and particularly its
[networking](https://www.kernel.org/doc/html/latest/process/maintainer-netdev.html#multi-line-comments)
flavor coding style for the BPF parts.

### Opening a pull-request

1. Before opening the pull-request, test the changes. Yes, even for those simple
   one-liner last minute changes.
1. Check the following commands do not return an error:
   1. `cargo fmt --check`
   1. `cargo clippy -- -D warnings`
   1. `cargo test`, or to include runtime tests,
      `CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER='sudo' cargo test --features=test_cap_bpf`
1. Make sure commits are
   [signed off](https://www.kernel.org/doc/html/latest/process/submitting-patches.html?highlight=signed%20off#developer-s-certificate-of-origin-1-1).
1. Use a clear, concise and descriptive title.
1. If the pull-request is linked to an issue, or based on top of another
   pull-request; reference those.
1. Describe the environment on which the feature is used and provide value.
1. Provide a detailed explanation of why the feature was added, how it was done
   and what is the expected output and behavior.
1. If applicable, provide a step-by-step guide on how to test the feature.
1. For pull-requests demonstrating a change to start a discussion, please add
   "[RFC]" in the pull-request title. Once in a state ready to be formally
   reviewed for inclusion, remove it.

### Following-up on the pull-request

1. As new versions of the pull-request are pushed, make sure to mark applicable
   conversations as
   [resolved](https://docs.github.com/en/github/collaborating-with-issues-and-pull-requests/commenting-on-a-pull-request#resolving-conversations).
1. If the pull-request has a conflict and cannot be merged, please rebase on the
   latest `main`. This can happen at any time, e.g. when other pull-requests are
   being merged.
