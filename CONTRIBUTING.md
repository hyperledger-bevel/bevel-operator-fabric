# Contributing to HLF Operator

Thank you for your interest in contributing to the HLF Operator! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Release Process](#release-process)

## Code of Conduct

This project follows the [Hyperledger Code of Conduct](https://wiki.hyperledger.org/display/HYP/Hyperledger+Code+of+Conduct). By participating, you are expected to uphold this code.

## Getting Started

### Prerequisites

- Go 1.23.5 or later
- Docker
- Kubernetes cluster (KIND, K3D, or similar for local development)
- kubectl
- Helm 3
- Make

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork:
   ```bash
   git clone https://github.com/<your-username>/bevel-operator-fabric.git
   cd bevel-operator-fabric
   ```
3. Add upstream remote:
   ```bash
   git remote add upstream https://github.com/hyperledger/bevel-operator-fabric.git
   ```

## Development Environment

### Setup

1. Install dependencies:
   ```bash
   go mod download
   ```

2. Install development tools:
   ```bash
   # Install controller-gen
   make controller-gen

   # Install golangci-lint
   make golangci-lint

   # Install pre-commit (optional but recommended)
   pip install pre-commit
   make pre-commit-install
   ```

3. Create a local Kubernetes cluster:
   ```bash
   kind create cluster --config .github/kind-config.yaml
   ```

4. Install CRDs:
   ```bash
   make install
   ```

### Running the Operator Locally

```bash
# Run against the configured cluster
make run
```

### Building

```bash
# Build the manager binary
make manager

# Build Docker image
make docker-build IMG=hlf-operator:dev
```

### Deploy (Development)

```bash
# Set the image name so that it always gets redeployed
export IMAGE=kfsoftware/hlf-operator:dev-$(date +%s%3N)

# Build the binary
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o hlf-operator ./main.go

# Build the docker image
docker build -t $IMAGE --platform=linux/amd64 .

# For K3D: import the images in all the nodes
k3d image import $IMAGE -c k8s-hlf

# For KIND: load the image
kind load docker-image $IMAGE --name kind

# Deploy the new version of the operator
make deploy IMG=$IMAGE
```

## Making Changes

### Branch Naming

Use descriptive branch names:
- `feature/add-vault-support`
- `fix/peer-connection-timeout`
- `docs/update-troubleshooting`
- `refactor/improve-reconciler`

### Code Style

- Follow Go best practices and idioms
- Run `make fmt` before committing
- Ensure `make lint` passes
- Add tests for new functionality
- Update documentation as needed

### Pre-commit Hooks

We use pre-commit hooks to ensure code quality:

```bash
# Install hooks
make pre-commit-install

# Run manually
make pre-commit
```

### Commit Messages

Use clear, descriptive commit messages:

```
<type>(<scope>): <subject>

<body>

<footer>
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

Example:
```
feat(peer): add support for external chaincode builder

Added configuration options to specify external chaincode builder
for Kubernetes-native chaincode deployment.

Closes #123
```

## Testing

### Running Tests

```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# View coverage report
make test-coverage-report

# Run short tests only (skip integration tests)
make test-short

# Run tests with verbose output
make test-verbose
```

### Test Requirements

- Unit tests should not require external dependencies
- Integration tests run in the `controllers/tests/` directory
- Tests require a Kubernetes cluster (use KIND for local testing)

### Writing Tests

Use Ginkgo/Gomega for BDD-style tests:

```go
var _ = Describe("FabricCA Controller", func() {
    Context("when creating a new CA", func() {
        It("should create the necessary resources", func() {
            // Test implementation
        })
    })
})
```

## Submitting Changes

### Pull Request Process

1. Update your fork:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. Create a feature branch:
   ```bash
   git checkout -b feature/my-feature
   ```

3. Make your changes and commit:
   ```bash
   git add .
   git commit -m "feat: add my feature"
   ```

4. Push to your fork:
   ```bash
   git push origin feature/my-feature
   ```

5. Create a Pull Request on GitHub

### PR Requirements

- [ ] Tests pass (`make test`)
- [ ] Linting passes (`make lint`)
- [ ] Code is formatted (`make fmt`)
- [ ] Documentation is updated if needed
- [ ] Commit messages follow conventions
- [ ] PR description explains the changes

### Code Review

- All PRs require at least one approval
- Address review comments promptly
- Keep PRs focused and reasonably sized
- Link related issues in the PR description

## Release Process

Releases are managed by maintainers using GitHub Actions:

1. **Version Bump**: Update version in relevant files
2. **Changelog**: Update CHANGELOG.md
3. **Tag**: Create and push a version tag
4. **Release**: GitHub Actions builds and publishes artifacts

### Versioning

We follow [Semantic Versioning](https://semver.org/):
- MAJOR: Breaking changes
- MINOR: New features (backward compatible)
- PATCH: Bug fixes (backward compatible)

## Getting Help

- **GitHub Issues**: For bugs and feature requests
- **Discussions**: For questions and general discussion
- **Discord**: Hyperledger Discord #fabric-operator channel

## Additional Resources

- [Operator SDK Documentation](https://sdk.operatorframework.io/docs/)
- [controller-runtime Documentation](https://pkg.go.dev/sigs.k8s.io/controller-runtime)
- [Hyperledger Fabric Documentation](https://hyperledger-fabric.readthedocs.io/)
- [Kubernetes API Conventions](https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md)

Thank you for contributing!
