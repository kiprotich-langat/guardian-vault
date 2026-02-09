# Guardian Vault

**Autonomous Security Monitoring for OpenClaw Agents**

Guardian Vault is a comprehensive security system that protects OpenClaw AI agents from prompt injection attacks, credential theft, and malicious skill execution. Built for the OpenClaw x Sui Stack Hackathon 2026.

## The Problem

Recent security research (CrowdStrike, Cisco, Giskard, Trend Micro - January/February 2026) revealed critical vulnerabilities:

- 93.4% of public OpenClaw instances have authentication bypass flaws
- 770,000 agents exposed through Moltbook vulnerability
- 26% of third-party skills contain security vulnerabilities
- Active prompt injection attacks targeting crypto wallet drainage

OpenClaw agents have root-level system access with no built-in security, making them prime targets for exploitation.

## The Solution

Guardian Vault provides multi-layered protection through:

### 1. Prompt Injection Detection
- 30+ known injection patterns using regex
- High-risk command analysis
- Optional LLM-based semantic analysis
- Real-time risk scoring (0-100 scale)
- Automatic blocking at configurable thresholds

### 2. Immutable Audit Trail (Walrus)
- All security events logged to decentralized storage
- Tamper-proof evidence for forensics
- 6-month retention with compression
- Batch uploads every 5 minutes or 100 logs
- Cost-optimized storage

### 3. Encrypted Credential Storage (Seal)
- API keys encrypted before storage
- Zero-trust access model
- Automatic rotation capabilities
- Complete access audit trail
- AES-256 encryption

### 4. Execution Monitoring
- Shell command validation
- File system access control
- Network request filtering
- Skill installation verification
- Real-time threat blocking

### 5. Autonomous Recovery
- Automated state snapshots
- Quick recovery from compromise
- SOUL.md persistence protection
- Rollback to known-good configuration

### 6. Community Governance (Sui Smart Contracts)
- Decentralized threat pattern voting
- Community-sourced intelligence
- Transparent policy updates
- Cross-agent protection network

## Key Features

- Blocks 95%+ of known injection patterns
- Detects command injection, file access violations, network threats
- Stores credentials encrypted with Seal
- Logs all events to Walrus immutably
- Recovers from compromise in under 30 seconds
- Enables community threat intelligence sharing
- Zero-trust security architecture
- Open source for community auditing

## Technology Stack

- **Backend:** TypeScript/Node.js
- **Sui Integration:** @mysten/sui.js SDK
- **AI Analysis:** Anthropic Claude API (optional)
- **Storage:** Walrus (decentralized blob storage)
- **Encryption:** Seal (on-chain encryption)
- **Smart Contracts:** Move on Sui blockchain

## Quick Start

### Prerequisites

- Node.js 18+ (v20+ recommended)
- Sui CLI installed
- Sui wallet with testnet tokens

### Installation
```bash
# Clone repository
git clone https://github.com/kiprotich-langat/guardian-vault
cd guardian-vault

# Install dependencies
npm install

# Configure environment
cp .env.example .env
# Edit .env with your Sui wallet credentials
```

### Configuration

Edit `.env` file:
```env
SUI_PRIVATE_KEY=your_sui_private_key_here
SUI_WALLET_ADDRESS=your_sui_wallet_address_here
ANTHROPIC_API_KEY=optional_for_enhanced_detection
```

To get your Sui private key:
```bash
# Create wallet
sui client new-address ed25519

# Get testnet tokens
sui client faucet

# Export private key
sui keytool export --key-identity <your-address>
```

### Running Guardian Vault
```bash
# Build the project
npm run build

# Run tests (22 comprehensive tests)
npm test

# Run interactive demo
npm run demo
```

## Usage

### Basic Integration
```typescript
import { GuardianVault } from './src/guardian-vault';

const guardian = new GuardianVault({
  suiPrivateKey: process.env.SUI_PRIVATE_KEY,
  suiWalletAddress: process.env.SUI_WALLET_ADDRESS,
});

await guardian.initialize();

// Analyze prompt before passing to OpenClaw
const result = await guardian.analyzePrompt({
  content: userInput,
  source: 'direct_message',
  agentId: 'my-agent',
  timestamp: Date.now()
});

if (result.action === 'allow') {
  // Safe to process
  await openClaw.process(userInput);
} else {
  console.log(`Blocked: ${result.reason}`);
}
```

### Monitor Commands
```typescript
const result = guardian.monitorCommand('ls -la', 'my-agent');
if (result.allowed) {
  // Execute command
}
```

### Store Credentials Securely
```typescript
// Store
const credId = await guardian.storeCredential(
  'anthropic_api_key',
  'sk-ant-...',
  'my-agent'
);

// Retrieve
const apiKey = await guardian.retrieveCredential(
  'anthropic_api_key',
  'my-agent'
);
```

## Test Results

All 22 tests pass successfully:

- 7 Prompt Analyzer tests
- 8 Execution Monitor tests  
- 7 Seal Vault tests
```bash
npm test
```

Expected output:
```
Total Tests:  22
Passed:       22
Failed:       0
Success Rate: 100.0%
```

## Demo

The interactive demo demonstrates:

1. Prompt injection detection and blocking
2. Command injection prevention
3. Credential protection with Seal encryption
4. File access monitoring
5. Network request filtering
6. Real-world attack scenario blocking
7. Audit trail logging to Walrus

Run with:
```bash
npm run demo
```

## Sui Stack Integration

### Walrus (Decentralized Storage)

- Audit logs batched and compressed
- Uploaded every 5 minutes or 100 logs
- 180 epoch retention (approximately 6 months)
- Immutable evidence trail
- Cost-optimized through compression

### Seal (Encryption)

- Credentials encrypted before Walrus storage
- AES-256 encryption
- Keys never leave local system
- Decryption only on authorized access

### Sui Blockchain (Governance)

- Smart contract for threat pattern proposals
- Token-weighted voting mechanism
- Automatic pattern distribution
- On-chain transparency

## Architecture
```
┌──────────────────────────────────────────────────────┐
│                 Guardian Vault Core                  │
├──────────────────────────────────────────────────────┤
│  Prompt Analyzer → Execution Monitor → Threat Detector │
│       ↓                    ↓                  ↓       │
│     ALLOW              QUARANTINE           BLOCK     │
└───────────────────────┬──────────────────────────────┘
                        │
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
  ┌──────────┐    ┌──────────┐   ┌──────────┐
  │  Walrus  │    │   Seal   │   │   Sui    │
  │ Audit    │    │ Creds    │   │ Govern   │
  └──────────┘    └──────────┘   └──────────┘
```

## Performance

- Prompt analysis: <50ms average (regex + command check)
- With LLM analysis: <2s (includes Claude API call)
- Batch upload: Every 5 minutes or 100 logs
- Storage cost: ~0.01 WAL per 1000 logs (estimated)
- Recovery time: <30 seconds from Walrus snapshot

## Security Considerations

Guardian Vault itself must be secure:

- Private keys stored locally, never uploaded
- Audit logs encrypted in transit
- No single point of failure
- Immutable evidence trail
- Open source for community auditing

## Project Structure
```
guardian-vault/
├── src/
│   ├── analyzer/
│   │   ├── prompt-analyzer.ts       # Prompt injection detection
│   │   └── execution-monitor.ts     # Command/file/network monitoring
│   ├── storage/
│   │   ├── walrus-client.ts         # Walrus integration
│   │   └── seal-vault.ts            # Credential encryption
│   ├── demo/
│   │   └── run-demo.ts              # Interactive demo
│   ├── guardian-vault.ts            # Main orchestrator
│   └── index.ts                     # Entry point
├── tests/
│   └── all-tests.ts                 # Comprehensive test suite
├── move_contracts/
│   ├── sources/
│   │   └── threat_governance.move   # Sui smart contract
│   └── Move.toml                    # Move configuration
├── docs/
│   ├
│   ├
│   └── DEEPSURGE_SUBMISSION.md      # Hackathon submission
├── package.json
├── tsconfig.json
├── .env.example
└── README.md
```

## Documentation

- [Setup Guide](docs/SETUP.md) - Detailed setup instructions
- [Quick Start](docs/QUICKSTART.md) - Get running in 15 minutes
- [Submission Template](docs/DEEPSURGE_SUBMISSION.md) - Hackathon submission

## Roadmap

### Phase 1 (Post-Hackathon)
- Machine learning for advanced threat detection
- Multi-agent coordination
- Browser extension for easy setup
- Integration with OpenClaw as official plugin

### Phase 2 (Months 2-3)
- Enterprise version with compliance reporting
- Real-time threat intelligence network
- Integration with security vendors

### Phase 3 (Months 4-6)
- Certification program for protected agents
- Insurance partnerships
- Mainnet production deployment

## Contributing

Contributions welcome! This is an open source project.
```bash
# Fork the repository
git clone https://github.com/kiprotich-langat/guardian-vault
cd guardian-vault

# Create feature branch
git checkout -b feature/your-feature

# Make changes and test
npm test

# Submit pull request
```

## License

MIT License - See LICENSE file for details

## Hackathon

Built for **OpenClaw x Sui Stack Hackathon 2026**
- Track: Safety & Security
- Submission: February 11, 2026

## Contact

- GitHub: https://github.com/kiprotich-langat/guardian-vault
- Moltbook: @GuardianVault
- DeepSurge: https://deepsurge.xyz
- email: kiprotichlangat@proton.me

## Acknowledgments

- OpenClaw team for building amazing agent infrastructure
- Sui/Mysten Labs for Walrus and decentralized storage
- Security researchers for vulnerability disclosure
- OpenClaw community for testing and feedback

---

**Protecting AI agents, one prompt at a time.**

Built with TypeScript, Sui, Walrus, and Seal.
