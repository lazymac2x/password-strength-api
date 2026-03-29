<p align="center"><img src="logo.png" width="120" alt="logo"></p>

[![lazymac API Store](https://img.shields.io/badge/lazymac-API%20Store-blue?style=flat-square)](https://lazymac2x.github.io/lazymac-api-store/) [![Gumroad](https://img.shields.io/badge/Buy%20on-Gumroad-ff69b4?style=flat-square)](https://coindany.gumroad.com/) [![MCPize](https://img.shields.io/badge/MCP-MCPize-green?style=flat-square)](https://mcpize.com/mcp/password-strength-api)

# password-strength-api

Password strength analysis API — scoring (0-100), entropy calculation, crack time estimation for 6 attack scenarios, pattern detection (keyboard walks, sequences, dates, leet speak, common words), policy validation, secure password generation (random, pronounceable, passphrase, PIN), and HIBP breach check. REST + MCP server.

## Quick Start

```bash
npm install && npm start  # http://localhost:3800
```

## Endpoints

### Analyze Password
```bash
curl -X POST http://localhost:3800/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"password": "MyP@ssw0rd123"}'
# → {score, strength, entropy, charsetAnalysis, patterns, crackTimes, suggestions}
```

### Quick Score
```bash
curl -X POST http://localhost:3800/api/v1/score \
  -H "Content-Type: application/json" \
  -d '{"password": "hunter2"}'
# → {score, label}
```

### Check Common Passwords
```bash
curl -X POST http://localhost:3800/api/v1/check-common \
  -H "Content-Type: application/json" \
  -d '{"password": "password123"}'
# → {isCommon: true, rank: 5, message: "..."}
```

### Validate Policy
```bash
curl -X POST http://localhost:3800/api/v1/validate \
  -H "Content-Type: application/json" \
  -d '{"password": "Test1234", "policy": {"minLength": 12, "requireSpecialChars": true}}'
# → {passed, score, results, failedRules}
```

### Generate Passwords
```bash
# Random
curl -X POST http://localhost:3800/api/v1/generate \
  -H "Content-Type: application/json" \
  -d '{"type": "random", "length": 20}'

# Passphrase (diceware-style)
curl -X POST http://localhost:3800/api/v1/generate \
  -H "Content-Type: application/json" \
  -d '{"type": "passphrase", "words": 5, "separator": "-"}'

# Pronounceable
curl -X POST http://localhost:3800/api/v1/generate \
  -H "Content-Type: application/json" \
  -d '{"type": "pronounceable", "length": 14}'
```

### Breach Check (HIBP k-anonymity)
```bash
curl -X POST http://localhost:3800/api/v1/breach-check \
  -H "Content-Type: application/json" \
  -d '{"password": "password"}'
# → {sha1Hash, prefix, suffix, apiUrl, howToUse}
```

### Batch Analysis (up to 100)
```bash
curl -X POST http://localhost:3800/api/v1/batch \
  -H "Content-Type: application/json" \
  -d '{"passwords": ["pass1", "Str0ng!P@ss", "12345"]}'
# → {summary: {total, averageScore, strengthDistribution}, results}
```

### MCP (JSON-RPC 2.0)
```bash
curl -X POST http://localhost:3800/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

**MCP Tools:** `analyze_password`, `check_common`, `validate_policy`, `generate_password`, `batch_analyze`

## License
MIT
