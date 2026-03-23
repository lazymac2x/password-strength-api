const express = require('express');
const cors = require('cors');
const {
  analyzePassword,
  calculateScore,
  validatePolicy,
  breachCheckInfo,
  isCommon,
  getRank,
} = require('./analyzer');
const { generate } = require('./generator');

const app = express();
const PORT = process.env.PORT || 3800;

app.use(cors());
app.use(express.json({ limit: '1mb' }));

// ============================================================
// MCP HTTP Endpoint (JSON-RPC 2.0 over POST /mcp)
// ============================================================

const MCP_SERVER_INFO = {
  name: 'password-strength-api',
  version: '1.0.0',
};

const MCP_TOOLS = [
  {
    name: 'analyze_password',
    description: 'Full password strength analysis: score (0-100), entropy, crack time estimates for 6 attack scenarios, pattern detection (keyboard walks, sequences, repeated chars, dates, common words, leet speak), suggestions for improvement.',
    inputSchema: {
      type: 'object',
      properties: {
        password: { type: 'string', description: 'The password to analyze' },
      },
      required: ['password'],
    },
  },
  {
    name: 'check_common',
    description: 'Check if a password is in the top 10,000 most common passwords. Returns whether it was found and its approximate rank.',
    inputSchema: {
      type: 'object',
      properties: {
        password: { type: 'string', description: 'The password to check' },
      },
      required: ['password'],
    },
  },
  {
    name: 'validate_policy',
    description: 'Validate a password against a configurable security policy. Checks length, character requirements, pattern rules, minimum score, and custom blacklist.',
    inputSchema: {
      type: 'object',
      properties: {
        password: { type: 'string', description: 'The password to validate' },
        policy: {
          type: 'object',
          description: 'Custom policy overrides',
          properties: {
            minLength: { type: 'number', description: 'Minimum length (default 8)' },
            maxLength: { type: 'number', description: 'Maximum length (default 128)' },
            requireUppercase: { type: 'boolean', description: 'Require uppercase (default true)' },
            requireLowercase: { type: 'boolean', description: 'Require lowercase (default true)' },
            requireDigits: { type: 'boolean', description: 'Require digits (default true)' },
            requireSpecialChars: { type: 'boolean', description: 'Require special chars (default false)' },
            minScore: { type: 'number', description: 'Minimum strength score 0-100 (default 40)' },
            disallowCommon: { type: 'boolean', description: 'Disallow common passwords (default true)' },
            customBlacklist: { type: 'array', items: { type: 'string' }, description: 'Custom blacklisted terms' },
          },
        },
      },
      required: ['password'],
    },
  },
  {
    name: 'generate_password',
    description: 'Generate secure passwords. Supports random, pronounceable, passphrase (diceware-style), and PIN generation with configurable options.',
    inputSchema: {
      type: 'object',
      properties: {
        type: { type: 'string', enum: ['random', 'pronounceable', 'passphrase', 'pin'], description: 'Generation type (default random)' },
        count: { type: 'number', description: 'Number of passwords to generate (default 1, max 50)' },
        length: { type: 'number', description: 'Password length for random/pronounceable (default 16)' },
        includeUppercase: { type: 'boolean', description: 'Include uppercase letters (default true)' },
        includeLowercase: { type: 'boolean', description: 'Include lowercase letters (default true)' },
        includeDigits: { type: 'boolean', description: 'Include digits (default true)' },
        includeSymbols: { type: 'boolean', description: 'Include symbols (default true)' },
        excludeAmbiguous: { type: 'boolean', description: 'Exclude ambiguous chars like Il1O0 (default false)' },
        words: { type: 'number', description: 'Number of words for passphrase (default 5)' },
        separator: { type: 'string', description: 'Word separator for passphrase (default -)' },
        capitalize: { type: 'boolean', description: 'Capitalize words in passphrase (default true)' },
        includeNumber: { type: 'boolean', description: 'Add number to passphrase (default true)' },
      },
    },
  },
  {
    name: 'batch_analyze',
    description: 'Analyze multiple passwords at once. Returns strength analysis for each password. Max 100 passwords per batch.',
    inputSchema: {
      type: 'object',
      properties: {
        passwords: {
          type: 'array',
          items: { type: 'string' },
          description: 'Array of passwords to analyze (max 100)',
        },
      },
      required: ['passwords'],
    },
  },
];

async function mcpExecuteTool(name, args) {
  switch (name) {
    case 'analyze_password': {
      const result = analyzePassword(args.password);
      return [{ type: 'text', text: JSON.stringify(result, null, 2) }];
    }
    case 'check_common': {
      const common = isCommon(args.password);
      const rank = getRank(args.password);
      return [{ type: 'text', text: JSON.stringify({ isCommon: common, rank, password: args.password.slice(0, 2) + '***' }, null, 2) }];
    }
    case 'validate_policy': {
      const result = validatePolicy(args.password, args.policy || {});
      return [{ type: 'text', text: JSON.stringify(result, null, 2) }];
    }
    case 'generate_password': {
      const password = generate(args);
      const result = typeof password === 'string'
        ? { password, analysis: analyzePassword(password) }
        : { passwords: password, count: password.length };
      return [{ type: 'text', text: JSON.stringify(result, null, 2) }];
    }
    case 'batch_analyze': {
      const passwords = (args.passwords || []).slice(0, 100);
      const results = passwords.map(pw => analyzePassword(pw));
      return [{ type: 'text', text: JSON.stringify({ count: results.length, results }, null, 2) }];
    }
    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

async function handleMcpRequest(body) {
  const { id, method, params } = body;

  switch (method) {
    case 'initialize':
      return {
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: '2024-11-05',
          capabilities: { tools: {} },
          serverInfo: MCP_SERVER_INFO,
        },
      };

    case 'notifications/initialized':
      return null;

    case 'tools/list':
      return {
        jsonrpc: '2.0',
        id,
        result: { tools: MCP_TOOLS },
      };

    case 'tools/call': {
      try {
        const content = await mcpExecuteTool(params.name, params.arguments || {});
        return {
          jsonrpc: '2.0',
          id,
          result: { content },
        };
      } catch (err) {
        return {
          jsonrpc: '2.0',
          id,
          result: {
            content: [{ type: 'text', text: `Error: ${err.message}` }],
            isError: true,
          },
        };
      }
    }

    default:
      return {
        jsonrpc: '2.0',
        id,
        error: { code: -32601, message: `Method not found: ${method}` },
      };
  }
}

app.post('/mcp', async (req, res) => {
  try {
    const result = await handleMcpRequest(req.body);
    if (result === null) return res.status(204).end();
    res.json(result);
  } catch (err) {
    res.status(500).json({
      jsonrpc: '2.0',
      id: req.body?.id || null,
      error: { code: -32603, message: `Internal error: ${err.message}` },
    });
  }
});

// ============================================================
// REST API Endpoints
// ============================================================

// Health check
app.get('/api/v1/health', (_req, res) => {
  res.json({ status: 'ok', service: 'password-strength-api', version: '1.0.0' });
});

// POST /api/v1/analyze — Full password analysis
app.post('/api/v1/analyze', (req, res) => {
  try {
    const { password } = req.body;
    if (!password) return res.status(400).json({ error: '"password" field is required' });
    res.json(analyzePassword(password));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/v1/score — Quick score only
app.post('/api/v1/score', (req, res) => {
  try {
    const { password } = req.body;
    if (!password) return res.status(400).json({ error: '"password" field is required' });
    const result = calculateScore(password);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/v1/check-common — Check against common passwords
app.post('/api/v1/check-common', (req, res) => {
  try {
    const { password } = req.body;
    if (!password) return res.status(400).json({ error: '"password" field is required' });
    const common = isCommon(password);
    const rank = getRank(password);
    res.json({
      isCommon: common,
      rank,
      message: common
        ? `This password is #${rank || '?'} in the most common passwords list. Do NOT use it.`
        : 'Not found in common passwords list.',
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/v1/validate — Validate against policy
app.post('/api/v1/validate', (req, res) => {
  try {
    const { password, policy } = req.body;
    if (!password) return res.status(400).json({ error: '"password" field is required' });
    res.json(validatePolicy(password, policy || {}));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/v1/generate — Generate passwords
app.post('/api/v1/generate', (req, res) => {
  try {
    const options = req.body || {};
    const password = generate(options);
    if (typeof password === 'string') {
      res.json({ password, analysis: analyzePassword(password) });
    } else {
      res.json({ passwords: password, count: password.length });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/v1/breach-check — Breach check info
app.post('/api/v1/breach-check', (req, res) => {
  try {
    const { password } = req.body;
    if (!password) return res.status(400).json({ error: '"password" field is required' });
    res.json(breachCheckInfo(password));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/v1/batch — Batch analysis
app.post('/api/v1/batch', (req, res) => {
  try {
    const { passwords } = req.body;
    if (!Array.isArray(passwords) || passwords.length === 0) {
      return res.status(400).json({ error: '"passwords" must be a non-empty array' });
    }
    if (passwords.length > 100) {
      return res.status(400).json({ error: 'Maximum 100 passwords per batch' });
    }
    const results = passwords.map(pw => analyzePassword(pw));
    const summary = {
      total: results.length,
      averageScore: Math.round(results.reduce((sum, r) => sum + (r.score || 0), 0) / results.length),
      strengthDistribution: {
        very_weak: results.filter(r => r.strength === 'very_weak' || r.strength === 'extremely_weak').length,
        weak: results.filter(r => r.strength === 'weak').length,
        fair: results.filter(r => r.strength === 'fair').length,
        strong: results.filter(r => r.strength === 'strong').length,
        very_strong: results.filter(r => r.strength === 'very_strong').length,
      },
      commonPasswordCount: results.filter(r => r.isCommon).length,
    };
    res.json({ summary, results });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Password Strength API running on http://localhost:${PORT}`);
  console.log('Endpoints:');
  console.log('  POST /api/v1/analyze        — Full password analysis');
  console.log('  POST /api/v1/score          — Quick strength score');
  console.log('  POST /api/v1/check-common   — Common password check');
  console.log('  POST /api/v1/validate       — Policy validation');
  console.log('  POST /api/v1/generate       — Generate passwords');
  console.log('  POST /api/v1/breach-check   — Breach check info (HIBP)');
  console.log('  POST /api/v1/batch          — Batch analysis');
  console.log('  GET  /api/v1/health         — Health check');
  console.log('  POST /mcp                   — MCP JSON-RPC endpoint');
});

module.exports = app;
