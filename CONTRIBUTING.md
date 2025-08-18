# Contributing to IP Address Parsing Solution

Thank you for your interest in contributing to this project! This document provides guidelines and information for contributors.

## How to Contribute

### Reporting Issues
- Use the issue tracker to report bugs or request new features
- Include detailed information about your environment and the issue
- Provide sample data when possible (ensure no sensitive information is included)

### Suggesting Enhancements
- Open an issue to discuss proposed changes before implementing
- Describe the use case and expected behavior
- Consider backward compatibility

### Code Contributions
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes following the coding standards below
4. Test your changes thoroughly
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## Coding Standards

### Python Code
- Follow PEP 8 style guidelines
- Use type hints where appropriate
- Include docstrings for all functions and classes
- Add comprehensive error handling
- Write unit tests for new functionality

### Documentation
- Update README.md for new features
- Include usage examples
- Document any new command-line arguments
- Update requirements.txt for new dependencies

### Security Considerations
- Validate all input data
- Prevent path traversal attacks
- Sanitize error messages
- Follow the principle of least privilege

## Testing

### Before Submitting
- Run existing tests to ensure they pass
- Add tests for new functionality
- Test with various input formats and edge cases
- Verify security features work as expected

### Test Data
- Use the sample files in the `tests/` directory
- Create new test cases for new features
- Ensure test data doesn't contain real IP addresses

## Pull Request Guidelines

### What to Include
- Clear description of changes
- Reference to related issues
- Screenshots for UI changes (if applicable)
- Test results and coverage information

### Review Process
- All contributions require review
- Address feedback and requested changes
- Ensure CI/CD checks pass
- Maintain clean commit history

## Getting Help

- Check existing issues and documentation
- Ask questions in the issue tracker
- Review the codebase to understand the architecture

## License

By contributing to this project, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to making this tool better for the cybersecurity community!
