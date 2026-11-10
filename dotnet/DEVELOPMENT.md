# AntiSSRF .NET Development

## Prerequisites

- Build and run `net8.0` tests: .NET 8.0 SDK or later, with the .NET 8.0 runtime (included with the .NET 8.0 SDK).
- Build and run `net48` tests: Windows, the .NET Framework 4.8 targeting pack, and .NET Framework 4.8 or later.

## Useful Commands

Run these commands from the `dotnet` directory.

### Restore and Build

- Restore dependencies: `dotnet restore`
- Build solution: `dotnet build`

### Run Tests

- Run all tests: `dotnet test`
- Run only .NET 8.0 tests: `dotnet test --framework net8.0`
- Run only .NET Framework 4.8 tests (Windows): `dotnet test --framework net48`
