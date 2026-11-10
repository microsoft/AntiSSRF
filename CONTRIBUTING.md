# Contributing to AntiSSRF

Thank you for your interest in contributing to Microsoft AntiSSRF! This guide will help you get started with contributing to our security library.

## Submitting Issues

We welcome all bug reports and feature requests. Please use our issue templates to ensure we have all the information we need.

### Bug Reports

- Report bugs through [GitHub Issues](https://github.com/microsoft/AntiSSRF/issues).
- Provide clear steps to reproduce the issue and describe the expected behavior.
- Include relevant version information and environment details.

### Feature Requests

- Submit feature requests through [GitHub Issues](https://github.com/microsoft/AntiSSRF/issues).
- Clearly describe the problem your feature would solve.
- Explain your proposed solution and any alternatives you have considered.
- Specify which libraries the feature applies to.

## Contributing PRs

To contribute bug fixes, features, or documentation improvements, follow the steps below.

### Before Implementation

Discussion with maintainers is required for all changes except trivial documentation or comment changes, such as fixing broken links or typos. All code changes, including test cases, require maintainer approval in an issue before implementation. When required, PRs opened without a linked issue may be closed.

1. Open a new issue or reopen an existing issue.
2. Describe the intended change and discuss it with maintainers.
3. Wait for a maintainer to confirm that the proposed change is ready for implementation.

### Before Publishing a PR

- Provide a detailed description of your changes in the PR summary.
- Link to the issue where a maintainer approved the proposed change, except in the case of trivial changes.
- If your PR includes code changes:
  - Ensure there are no breaking changes unless maintainers have explicitly approved them.
  - Add appropriate test coverage for the changes.
  - Documentation updates are optional but greatly appreciated.

## General Considerations

- Breaking changes - All other possibilities must be considered before introducing a change that could break existing functionality.
- Configuration file changes - Modifications to IP address ranges or domains configuration files will almost always be rejected unless there is an exceptional reason.

We appreciate the time and care you put into your contributions! Unfortunately, all the maintainers balance reviews with other commitments, so it may take a little while before someone is available to review your issue or pull request. Thank you for your patience and understanding.
