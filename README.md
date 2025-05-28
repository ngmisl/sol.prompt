# sol.prompt

A high-performance, type-safe Go tool that prepares Solidity smart contracts for AI-powered security auditing. Extracts, analyzes, and optimizes contract code to create LLM-ready audit prompts with security-focused organization.

## 🔍 Features

### Core Functionality
- **Smart Contract Analysis**: Automatically discovers and processes all `.sol` files in a directory
- **Security-First Organization**: Prioritizes critical functions and high-risk code patterns (internal analysis)
- **LLM Optimization**: Generates XML-structured output containing cleaned contract code, optimized for AI security analysis
- **Risk Assessment**: Identifies and categorizes security risks in smart contracts
- **Concurrent Processing**: High-performance parallel file processing with worker pools

### Security Analysis
- **Vulnerability Detection**: Identifies common patterns like reentrancy, tx.origin usage, delegatecall risks
- **Access Control Analysis**: Extracts and highlights permission-based functions
- **Function Categorization**: Classifies functions by risk level (Critical/High/Medium/Low)
- **Modifier Extraction**: Identifies security modifiers and access controls
- **Token Estimation**: Estimates output size for LLM context limits

### Code Intelligence
- **Type-Safe Processing**: Robust error handling with recovery mechanisms
- **Smart Filtering**: Removes test code, comments, and irrelevant imports
- **Dependency Tracking**: Maps contract relationships and inheritance
- **Risk Scoring**: Quantitative risk assessment for each contract

## 🚀 Installation

### Prerequisites
- Go 1.23 or later
- Access to Solidity contract files

### Install from Source
```bash
git clone <repository-url>
cd sol.prompt
go build -o sol.prompt .
```

### Direct Run
```bash
go run . <path-to-contracts>
```

## 📖 Usage

### Basic Usage
```bash
# Analyze contracts in current directory
./sol.prompt ./contracts

# Analyze with security focus
./sol.prompt ./contracts --security-focus

# Include private functions
./sol.prompt ./contracts --include-private
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--security-focus` | Enhanced security analysis and risk detection | `false` |
| `--include-private` | Include private/internal functions in output | `false` |
| `--include-test` | Include test-related imports and functions | `false` |
| `--optimize-gpt` | Optimize output format for GPT models | `generic` |
| `--optimize-claude` | Optimize output format for Claude models | `generic` |

### Examples

```bash
# Full security audit preparation
./sol.prompt ./src/contracts --security-focus --include-private

# Quick audit for public functions only
./sol.prompt ./contracts 

# Optimize for specific LLM
./sol.prompt ./contracts --optimize-claude --security-focus
```

## 📄 Output Format

The tool generates a `sol.prompt` file in XML format. This file contains the cleaned content of each processed Solidity contract, structured for easy parsing and ingestion by other tools or LLMs.

The basic XML structure is as follows:

```xml
<contracts>
  <contract name="ContractA.sol">
    <![CDATA[
// Cleaned content of ContractA.sol
// (pragma directives, imports, contract code, etc.)
// ...
// All elements of the contract are concatenated here.
    ]]>
  </contract>
  <contract name="ContractB.sol">
    <![CDATA[
// Cleaned content of ContractB.sol
// ...
    ]]>
  </contract>
  <!-- Additional contracts follow the same pattern -->
</contracts>
```

Key aspects of the XML output:
- Each Solidity file is represented by a `<contract>` element.
- The `name` attribute of the `<contract>` tag holds the original filename.
- The entire cleaned content of the contract is placed within a `<![CDATA[...]]>` section. This ensures that all Solidity syntax, including special characters, is preserved literally and doesn't interfere with XML parsing.
- The "cleaned content" consists of the concatenated `Content` of all code elements extracted from the Solidity file, in their original order. This typically includes pragma directives, import statements, contract definitions, functions, state variables, etc., after non-essential comments (excluding NatSpec and special annotations) have been stripped.

## 🔒 Security Focus Areas

The tool automatically identifies and highlights:

### Critical Patterns
- Financial operations (transfer, withdraw, mint, burn)
- Access control functions (onlyOwner, onlyAdmin)
- Dangerous operations (delegatecall, selfdestruct)
- External calls and value transfers

### Risk Factors
- **Reentrancy vulnerabilities**
- **tx.origin authentication**
- **Block timestamp dependencies**
- **Unchecked arithmetic operations**
- **Assembly usage**
- **Direct call.value transfers**

### Function Categories
- **Financial**: Money-related operations
- **Access**: Permission and role management  
- **State**: State-changing functions
- **View**: Read-only functions
- **Utility**: Helper and internal functions

## 🎯 LLM Integration

### Optimized for AI Analysis
- **XML structure** for easy parsing by LLMs and other tools
- **Context-aware token management** to stay within limits (internal estimation)

### Token Management
- Automatic token estimation for each contract
- Warning when approaching LLM context limits (100,000 tokens)
- Smart filtering to include only security-relevant code

### AI Model Optimization
- **Generic**: Balanced output for any LLM
- **GPT**: Optimized for OpenAI GPT models
- **Claude**: Optimized for Anthropic Claude models

## 📊 Performance

### Specifications
- **Concurrent Processing**: Up to 8 parallel workers
- **File Size Limit**: 50MB per contract file
- **Memory Efficient**: Streaming processing for large codebases
- **Error Recovery**: Continues processing despite individual file errors

### Benchmarks
- Processes ~1,000 lines of Solidity per second
- Handles entire DeFi protocol codebases (100+ contracts)
- Reduces code size by 60-80% while preserving security relevance

## 🛠️ Development

### Project Structure
```
sol.prompt/
├── main.go                 # Core application logic
├── go.mod                  # Go module definition
├── README.md              # This file
└── examples/              # Example usage and outputs
    ├── sample-contracts/   # Test Solidity files
    └── sample-output.xml   # Example sol.prompt output
```

### Building
```bash
# Build for current platform
go build -o sol.prompt .

# Cross-compile for Linux
GOOS=linux GOARCH=amd64 go build -o sol.prompt-linux .

# Cross-compile for Windows
GOOS=windows GOARCH=amd64 go build -o sol.prompt.exe .
```

### Testing
```bash
# Run with sample contracts
go run . ./examples/sample-contracts --security-focus

# Test concurrent processing
go run . ./large-codebase --include-private
```

## 🤝 Contributing

### Development Setup
1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes with proper error handling
4. Add tests for new functionality
5. Submit a pull request

### Code Standards
- Follow Go conventions and formatting (`go fmt`)
- Include comprehensive error handling
- Add security pattern recognition for new vulnerability types
- Maintain type safety and performance optimization

### Feature Requests
We welcome contributions for:
- New security pattern detection
- Additional LLM optimizations
- Performance improvements
- Enhanced risk scoring algorithms

## 📋 Roadmap

- [ ] **v2.0**: GraphQL API for integration with audit platforms
- [ ] **v2.1**: Real-time contract monitoring and diff analysis  
- [ ] **v2.2**: Integration with popular development frameworks
- [ ] **v2.3**: Machine learning-based risk scoring
- [ ] **v2.4**: Multi-language support (Vyper, Move, etc.)

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Solidity compiler team for language specifications
- OpenZeppelin for security pattern references
- Trail of Bits for audit methodology inspiration
- Go team for excellent concurrency primitives

## 📞 Support

For questions, issues, or feature requests:
- Create an issue on GitHub
- Join our Discord community
- Follow us on Twitter for updates

---

**sol.prompt** - Making smart contract security auditing more accessible and efficient through AI-powered analysis.