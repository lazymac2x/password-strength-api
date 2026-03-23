/**
 * Password Strength Analyzer
 * Comprehensive password analysis: entropy, crack time, pattern detection, scoring
 */

const crypto = require('crypto');
const { isCommon, getRank } = require('./common-passwords');

// ============================================================
// Character set analysis
// ============================================================

const CHARSETS = {
  lowercase: { regex: /[a-z]/, size: 26, label: 'lowercase letters' },
  uppercase: { regex: /[A-Z]/, size: 26, label: 'uppercase letters' },
  digits: { regex: /[0-9]/, size: 10, label: 'digits' },
  symbols: { regex: /[^a-zA-Z0-9]/, size: 33, label: 'special characters' },
  space: { regex: / /, size: 1, label: 'spaces' },
};

function analyzeCharsets(password) {
  const found = [];
  let poolSize = 0;

  for (const [name, cs] of Object.entries(CHARSETS)) {
    if (cs.regex.test(password)) {
      found.push({ name, label: cs.label, size: cs.size });
      poolSize += cs.size;
    }
  }

  // Check for extended unicode
  if (/[^\x00-\x7F]/.test(password)) {
    found.push({ name: 'unicode', label: 'unicode characters', size: 100 });
    poolSize += 100;
  }

  return { charsets: found, poolSize, diversity: found.length };
}

// ============================================================
// Entropy calculation
// ============================================================

function calculateEntropy(password) {
  const { poolSize } = analyzeCharsets(password);
  if (poolSize === 0 || password.length === 0) return 0;

  // Shannon entropy based on actual character frequencies
  const freq = {};
  for (const ch of password) {
    freq[ch] = (freq[ch] || 0) + 1;
  }

  let shannonEntropy = 0;
  const len = password.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    shannonEntropy -= p * Math.log2(p);
  }

  // Combinatorial entropy: log2(poolSize^length)
  const combinatorialEntropy = password.length * Math.log2(poolSize);

  // Effective entropy accounts for patterns reducing actual entropy
  const patternPenalty = calculatePatternPenalty(password);
  const effectiveEntropy = Math.max(0, combinatorialEntropy * (1 - patternPenalty));

  return {
    shannon: Math.round(shannonEntropy * 100) / 100,
    combinatorial: Math.round(combinatorialEntropy * 100) / 100,
    effective: Math.round(effectiveEntropy * 100) / 100,
  };
}

function calculatePatternPenalty(password) {
  let penalty = 0;
  const patterns = detectPatterns(password);

  if (patterns.repeatedChars.length > 0) penalty += 0.15;
  if (patterns.sequences.length > 0) penalty += 0.15;
  if (patterns.keyboardWalks.length > 0) penalty += 0.10;
  if (patterns.dates.length > 0) penalty += 0.10;
  if (patterns.commonWords.length > 0) penalty += 0.20;
  if (patterns.leetSpeak) penalty += 0.05;

  return Math.min(penalty, 0.70); // Cap at 70% penalty
}

// ============================================================
// Pattern detection
// ============================================================

const KEYBOARD_ROWS = [
  'qwertyuiop',
  'asdfghjkl',
  'zxcvbnm',
  '1234567890',
  '!@#$%^&*()',
];

const KEYBOARD_ADJACENT = buildAdjacencyMap();

function buildAdjacencyMap() {
  const rows = [
    '`1234567890-=',
    'qwertyuiop[]\\',
    'asdfghjkl;\'',
    'zxcvbnm,./',
  ];
  const map = {};
  for (const row of rows) {
    for (let i = 0; i < row.length; i++) {
      map[row[i]] = new Set();
      if (i > 0) map[row[i]].add(row[i - 1]);
      if (i < row.length - 1) map[row[i]].add(row[i + 1]);
    }
  }
  return map;
}

function detectKeyboardWalks(password) {
  const walks = [];
  const lower = password.toLowerCase();
  let current = '';

  for (let i = 0; i < lower.length; i++) {
    if (i === 0) {
      current = lower[i];
      continue;
    }

    const prev = lower[i - 1];
    const curr = lower[i];
    const isAdjacent = KEYBOARD_ADJACENT[prev]?.has(curr);

    // Also check keyboard rows
    let isRowWalk = false;
    for (const row of KEYBOARD_ROWS) {
      const pi = row.indexOf(prev);
      const ci = row.indexOf(curr);
      if (pi !== -1 && ci !== -1 && Math.abs(pi - ci) === 1) {
        isRowWalk = true;
        break;
      }
    }

    if (isAdjacent || isRowWalk) {
      current += lower[i];
    } else {
      if (current.length >= 3) {
        walks.push({ pattern: current, start: i - current.length, length: current.length });
      }
      current = lower[i];
    }
  }
  if (current.length >= 3) {
    walks.push({ pattern: current, start: lower.length - current.length, length: current.length });
  }

  return walks;
}

function detectSequences(password) {
  const sequences = [];
  let run = 1;
  let direction = 0; // 1=ascending, -1=descending

  for (let i = 1; i < password.length; i++) {
    const diff = password.charCodeAt(i) - password.charCodeAt(i - 1);

    if (diff === 1 || diff === -1) {
      if (run === 1) {
        direction = diff;
        run = 2;
      } else if (diff === direction) {
        run++;
      } else {
        if (run >= 3) {
          sequences.push({
            pattern: password.slice(i - run, i),
            type: direction === 1 ? 'ascending' : 'descending',
            start: i - run,
            length: run,
          });
        }
        direction = diff;
        run = 2;
      }
    } else {
      if (run >= 3) {
        sequences.push({
          pattern: password.slice(i - run, i),
          type: direction === 1 ? 'ascending' : 'descending',
          start: i - run,
          length: run,
        });
      }
      run = 1;
      direction = 0;
    }
  }
  if (run >= 3) {
    sequences.push({
      pattern: password.slice(password.length - run),
      type: direction === 1 ? 'ascending' : 'descending',
      start: password.length - run,
      length: run,
    });
  }

  return sequences;
}

function detectRepeatedChars(password) {
  const repeats = [];
  let i = 0;

  while (i < password.length) {
    let j = i + 1;
    while (j < password.length && password[j] === password[i]) j++;
    const run = j - i;
    if (run >= 3) {
      repeats.push({
        char: password[i],
        count: run,
        start: i,
        pattern: password.slice(i, j),
      });
    }
    i = j;
  }

  // Also detect repeated groups (e.g., "abcabc")
  for (let groupLen = 2; groupLen <= Math.floor(password.length / 2); groupLen++) {
    for (let start = 0; start <= password.length - groupLen * 2; start++) {
      const group = password.slice(start, start + groupLen);
      let count = 1;
      let pos = start + groupLen;
      while (pos + groupLen <= password.length && password.slice(pos, pos + groupLen) === group) {
        count++;
        pos += groupLen;
      }
      if (count >= 2 && groupLen * count >= 4) {
        repeats.push({
          char: group,
          count,
          start,
          pattern: group.repeat(count),
          type: 'repeated_group',
        });
      }
    }
  }

  return repeats;
}

function detectDates(password) {
  const dates = [];
  const datePatterns = [
    // MMDDYYYY, DDMMYYYY
    { regex: /\b(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])(19|20)\d{2}\b/g, format: 'MMDDYYYY' },
    { regex: /(0[1-9]|[12]\d|3[01])(0[1-9]|1[0-2])(19|20)\d{2}/g, format: 'DDMMYYYY' },
    // YYYY-MM-DD, YYYY/MM/DD
    { regex: /(19|20)\d{2}[-/](0[1-9]|1[0-2])[-/](0[1-9]|[12]\d|3[01])/g, format: 'YYYY-MM-DD' },
    // MM/DD/YYYY, DD/MM/YYYY
    { regex: /(0[1-9]|1[0-2])\/(0[1-9]|[12]\d|3[01])\/(19|20)\d{2}/g, format: 'MM/DD/YYYY' },
    // YYYYMMDD
    { regex: /(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])/g, format: 'YYYYMMDD' },
    // 2-digit year patterns
    { regex: /\b(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{2}\b/g, format: 'MMDDYY' },
    // Bare years
    { regex: /\b(19[5-9]\d|20[0-2]\d)\b/g, format: 'YYYY' },
  ];

  for (const dp of datePatterns) {
    let match;
    while ((match = dp.regex.exec(password)) !== null) {
      dates.push({
        match: match[0],
        format: dp.format,
        start: match.index,
      });
    }
  }

  return dates;
}

const COMMON_WORDS = [
  'password','pass','admin','user','login','welcome','hello','world',
  'test','guest','root','super','master','access','secret','private',
  'public','server','system','network','security','internet','computer',
  'love','baby','angel','princess','dragon','monkey','shadow','sunshine',
  'flower','summer','winter','spring','autumn','cookie','lucky','happy',
  'soccer','football','baseball','hockey','tennis','golf','fish','tiger',
  'lion','bear','wolf','eagle','hawk','snake','horse','bunny','puppy',
  'kitty','buddy','max','bella','charlie','lucy','daisy','rocky','jack',
  'star','moon','sun','fire','ice','storm','thunder','rain','snow','wind',
  'rock','metal','gold','silver','iron','steel','diamond','crystal',
  'blue','red','green','black','white','dark','light','bright','cool',
  'king','queen','prince','knight','warrior','ninja','pirate','hero',
  'magic','power','force','energy','speed','fury','rage','doom','death',
  'life','soul','spirit','ghost','phantom','demon','devil','angel',
];

function detectCommonWords(password) {
  const found = [];
  const lower = password.toLowerCase();

  for (const word of COMMON_WORDS) {
    if (word.length < 3) continue;
    let idx = lower.indexOf(word);
    while (idx !== -1) {
      found.push({ word, start: idx, length: word.length });
      idx = lower.indexOf(word, idx + 1);
    }
  }

  return found;
}

function detectLeetSpeak(password) {
  const leetMap = { '@': 'a', '4': 'a', '3': 'e', '1': 'i', '!': 'i', '0': 'o', '5': 's', '$': 's', '7': 't', '+': 't' };
  let decoded = '';
  let hasLeet = false;

  for (const ch of password) {
    if (leetMap[ch]) {
      decoded += leetMap[ch];
      hasLeet = true;
    } else {
      decoded += ch.toLowerCase();
    }
  }

  if (!hasLeet) return null;

  // Check if decoded version matches common words
  const words = detectCommonWords(decoded);
  if (words.length > 0 || isCommon(decoded)) {
    return { decoded, matchedWords: words, isCommonDecoded: isCommon(decoded) };
  }

  return null;
}

function detectPatterns(password) {
  return {
    keyboardWalks: detectKeyboardWalks(password),
    sequences: detectSequences(password),
    repeatedChars: detectRepeatedChars(password),
    dates: detectDates(password),
    commonWords: detectCommonWords(password),
    leetSpeak: detectLeetSpeak(password),
  };
}

// ============================================================
// Crack time estimation
// ============================================================

const ATTACK_SCENARIOS = {
  online_throttled: {
    label: 'Online attack (throttled, 10/sec)',
    guessesPerSecond: 10,
    description: 'Rate-limited online service with lockout',
  },
  online_unthrottled: {
    label: 'Online attack (unthrottled, 1K/sec)',
    guessesPerSecond: 1e3,
    description: 'Online service without rate limiting',
  },
  offline_slow_hash: {
    label: 'Offline attack (bcrypt/scrypt, 10K/sec)',
    guessesPerSecond: 1e4,
    description: 'Offline attack on bcrypt/scrypt/argon2 hashes',
  },
  offline_fast_hash: {
    label: 'Offline attack (MD5/SHA1, 10B/sec)',
    guessesPerSecond: 1e10,
    description: 'Offline attack on unsalted MD5/SHA1 with modern GPU',
  },
  gpu_cluster: {
    label: 'GPU cluster (100B/sec)',
    guessesPerSecond: 1e11,
    description: 'Distributed GPU cluster attack',
  },
  massive_cluster: {
    label: 'State-level (1T/sec)',
    guessesPerSecond: 1e12,
    description: 'Nation-state level computing resources',
  },
};

function formatDuration(seconds) {
  if (seconds < 0.001) return 'instant';
  if (seconds < 1) return `${Math.round(seconds * 1000)} milliseconds`;
  if (seconds < 60) return `${Math.round(seconds)} seconds`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
  if (seconds < 86400 * 30) return `${Math.round(seconds / 86400)} days`;
  if (seconds < 86400 * 365) return `${Math.round(seconds / (86400 * 30))} months`;
  if (seconds < 86400 * 365 * 1000) return `${Math.round(seconds / (86400 * 365))} years`;
  if (seconds < 86400 * 365 * 1e6) return `${Math.round(seconds / (86400 * 365 * 1000))} thousand years`;
  if (seconds < 86400 * 365 * 1e9) return `${Math.round(seconds / (86400 * 365 * 1e6))} million years`;
  if (seconds < 86400 * 365 * 1e12) return `${Math.round(seconds / (86400 * 365 * 1e9))} billion years`;
  return `${(seconds / (86400 * 365 * 1e12)).toExponential(1)} trillion years`;
}

function estimateCrackTime(password) {
  const entropy = calculateEntropy(password);
  const guessSpace = Math.pow(2, entropy.effective);

  const crackTimes = {};
  for (const [key, scenario] of Object.entries(ATTACK_SCENARIOS)) {
    const seconds = guessSpace / (2 * scenario.guessesPerSecond); // Average: half the space
    crackTimes[key] = {
      label: scenario.label,
      description: scenario.description,
      guessesPerSecond: scenario.guessesPerSecond,
      seconds: Math.round(seconds * 100) / 100,
      display: formatDuration(seconds),
    };
  }

  return crackTimes;
}

// ============================================================
// Strength scoring (0-100)
// ============================================================

function calculateScore(password) {
  if (!password || password.length === 0) return { score: 0, label: 'empty', details: {} };

  const entropy = calculateEntropy(password);
  const charInfo = analyzeCharsets(password);
  const patterns = detectPatterns(password);
  const common = isCommon(password);
  const commonRank = getRank(password);

  // If in common password list, hard cap
  if (common) {
    return {
      score: Math.min(5, commonRank ? Math.max(1, Math.floor(5 * (commonRank / 10000))) : 3),
      label: 'extremely_weak',
      details: { reason: 'Found in common password list', rank: commonRank },
    };
  }

  let score = 0;

  // Length contribution (0-30 points)
  const lenScore = Math.min(30, password.length * 2.5);
  score += lenScore;

  // Charset diversity (0-20 points)
  const diversityScore = Math.min(20, charInfo.diversity * 5);
  score += diversityScore;

  // Entropy contribution (0-30 points)
  const entropyScore = Math.min(30, (entropy.effective / 100) * 30);
  score += entropyScore;

  // Unique characters ratio (0-10 points)
  const uniqueChars = new Set(password).size;
  const uniqueRatio = uniqueChars / password.length;
  score += uniqueRatio * 10;

  // Bonus for length > 16 (0-10 points)
  if (password.length > 16) {
    score += Math.min(10, (password.length - 16) * 1.5);
  }

  // Pattern penalties
  if (patterns.keyboardWalks.length > 0) score -= 10;
  if (patterns.sequences.length > 0) score -= 10;
  if (patterns.repeatedChars.length > 0) score -= 10;
  if (patterns.dates.length > 0) score -= 5;
  if (patterns.commonWords.length > 0) score -= 15;
  if (patterns.leetSpeak) score -= 5;

  // Short password penalty
  if (password.length < 8) score -= 20;
  else if (password.length < 10) score -= 10;

  score = Math.max(0, Math.min(100, Math.round(score)));

  let label;
  if (score <= 20) label = 'very_weak';
  else if (score <= 40) label = 'weak';
  else if (score <= 60) label = 'fair';
  else if (score <= 80) label = 'strong';
  else label = 'very_strong';

  return { score, label };
}

// ============================================================
// Full analysis
// ============================================================

function analyzePassword(password) {
  if (!password || typeof password !== 'string') {
    return { error: 'Password must be a non-empty string' };
  }

  const { score, label, details } = calculateScore(password);
  const entropy = calculateEntropy(password);
  const charInfo = analyzeCharsets(password);
  const patterns = detectPatterns(password);
  const crackTimes = estimateCrackTime(password);
  const common = isCommon(password);
  const commonRank = getRank(password);

  // Generate improvement suggestions
  const suggestions = [];
  if (password.length < 12) suggestions.push('Use at least 12 characters');
  if (password.length < 16) suggestions.push('Consider using 16+ characters for strong security');
  if (charInfo.diversity < 3) suggestions.push('Mix uppercase, lowercase, digits, and symbols');
  if (!charInfo.charsets.find(c => c.name === 'uppercase')) suggestions.push('Add uppercase letters');
  if (!charInfo.charsets.find(c => c.name === 'symbols')) suggestions.push('Add special characters (!@#$%^&*)');
  if (!charInfo.charsets.find(c => c.name === 'digits')) suggestions.push('Add digits');
  if (patterns.keyboardWalks.length > 0) suggestions.push('Avoid keyboard patterns like "qwerty" or "asdf"');
  if (patterns.sequences.length > 0) suggestions.push('Avoid sequential characters like "123" or "abc"');
  if (patterns.repeatedChars.length > 0) suggestions.push('Avoid repeating characters');
  if (patterns.dates.length > 0) suggestions.push('Avoid dates — they are easily guessable');
  if (patterns.commonWords.length > 0) suggestions.push('Avoid common dictionary words');
  if (patterns.leetSpeak) suggestions.push('Leet speak substitutions (@ for a, 3 for e) are well-known');
  if (common) suggestions.push('This is one of the most commonly used passwords — change it immediately');
  if (new Set(password).size < password.length * 0.5) suggestions.push('Use more unique characters');

  return {
    password: password.slice(0, 2) + '*'.repeat(Math.max(0, password.length - 2)),
    length: password.length,
    score,
    strength: label,
    entropy,
    charsetAnalysis: {
      charsets: charInfo.charsets.map(c => c.label),
      poolSize: charInfo.poolSize,
      diversity: charInfo.diversity,
      uniqueChars: new Set(password).size,
    },
    patterns: {
      keyboardWalks: patterns.keyboardWalks,
      sequences: patterns.sequences,
      repeatedChars: patterns.repeatedChars,
      dates: patterns.dates,
      commonWords: patterns.commonWords,
      leetSpeak: patterns.leetSpeak,
      patternCount: [
        ...patterns.keyboardWalks,
        ...patterns.sequences,
        ...patterns.repeatedChars,
        ...patterns.dates,
        ...patterns.commonWords,
      ].length + (patterns.leetSpeak ? 1 : 0),
    },
    crackTimes,
    isCommon: common,
    commonRank,
    suggestions,
  };
}

// ============================================================
// Policy validation
// ============================================================

const DEFAULT_POLICY = {
  minLength: 8,
  maxLength: 128,
  requireUppercase: true,
  requireLowercase: true,
  requireDigits: true,
  requireSpecialChars: false,
  minUppercase: 1,
  minLowercase: 1,
  minDigits: 1,
  minSpecialChars: 0,
  minUniqueChars: 4,
  maxRepeatedChars: 3,
  disallowCommon: true,
  disallowSequences: true,
  disallowKeyboardWalks: true,
  minScore: 40,
  customBlacklist: [],
};

function validatePolicy(password, userPolicy = {}) {
  const policy = { ...DEFAULT_POLICY, ...userPolicy };
  const results = [];
  let passed = true;

  // Length checks
  if (password.length < policy.minLength) {
    results.push({ rule: 'minLength', passed: false, message: `Must be at least ${policy.minLength} characters (got ${password.length})` });
    passed = false;
  } else {
    results.push({ rule: 'minLength', passed: true, message: `Length ${password.length} >= ${policy.minLength}` });
  }

  if (password.length > policy.maxLength) {
    results.push({ rule: 'maxLength', passed: false, message: `Must be at most ${policy.maxLength} characters` });
    passed = false;
  }

  // Character class checks
  const upperCount = (password.match(/[A-Z]/g) || []).length;
  const lowerCount = (password.match(/[a-z]/g) || []).length;
  const digitCount = (password.match(/[0-9]/g) || []).length;
  const specialCount = (password.match(/[^a-zA-Z0-9]/g) || []).length;
  const uniqueCount = new Set(password).size;

  if (policy.requireUppercase && upperCount < policy.minUppercase) {
    results.push({ rule: 'requireUppercase', passed: false, message: `Need at least ${policy.minUppercase} uppercase letter(s) (got ${upperCount})` });
    passed = false;
  } else if (policy.requireUppercase) {
    results.push({ rule: 'requireUppercase', passed: true, message: `Has ${upperCount} uppercase letter(s)` });
  }

  if (policy.requireLowercase && lowerCount < policy.minLowercase) {
    results.push({ rule: 'requireLowercase', passed: false, message: `Need at least ${policy.minLowercase} lowercase letter(s) (got ${lowerCount})` });
    passed = false;
  } else if (policy.requireLowercase) {
    results.push({ rule: 'requireLowercase', passed: true, message: `Has ${lowerCount} lowercase letter(s)` });
  }

  if (policy.requireDigits && digitCount < policy.minDigits) {
    results.push({ rule: 'requireDigits', passed: false, message: `Need at least ${policy.minDigits} digit(s) (got ${digitCount})` });
    passed = false;
  } else if (policy.requireDigits) {
    results.push({ rule: 'requireDigits', passed: true, message: `Has ${digitCount} digit(s)` });
  }

  if (policy.requireSpecialChars && specialCount < policy.minSpecialChars) {
    results.push({ rule: 'requireSpecialChars', passed: false, message: `Need at least ${policy.minSpecialChars} special character(s) (got ${specialCount})` });
    passed = false;
  } else if (policy.requireSpecialChars) {
    results.push({ rule: 'requireSpecialChars', passed: true, message: `Has ${specialCount} special character(s)` });
  }

  if (uniqueCount < policy.minUniqueChars) {
    results.push({ rule: 'minUniqueChars', passed: false, message: `Need at least ${policy.minUniqueChars} unique characters (got ${uniqueCount})` });
    passed = false;
  } else {
    results.push({ rule: 'minUniqueChars', passed: true, message: `Has ${uniqueCount} unique characters` });
  }

  // Pattern checks
  const patterns = detectPatterns(password);

  if (policy.disallowCommon && isCommon(password)) {
    results.push({ rule: 'disallowCommon', passed: false, message: 'Password is in the common password list' });
    passed = false;
  } else if (policy.disallowCommon) {
    results.push({ rule: 'disallowCommon', passed: true, message: 'Not in common password list' });
  }

  if (policy.disallowSequences && patterns.sequences.length > 0) {
    results.push({ rule: 'disallowSequences', passed: false, message: `Contains sequential pattern: "${patterns.sequences[0].pattern}"` });
    passed = false;
  } else if (policy.disallowSequences) {
    results.push({ rule: 'disallowSequences', passed: true, message: 'No sequential patterns found' });
  }

  if (policy.disallowKeyboardWalks && patterns.keyboardWalks.length > 0) {
    results.push({ rule: 'disallowKeyboardWalks', passed: false, message: `Contains keyboard walk: "${patterns.keyboardWalks[0].pattern}"` });
    passed = false;
  } else if (policy.disallowKeyboardWalks) {
    results.push({ rule: 'disallowKeyboardWalks', passed: true, message: 'No keyboard walk patterns found' });
  }

  // Repeated chars check
  const maxRepeat = findMaxRepeat(password);
  if (maxRepeat > policy.maxRepeatedChars) {
    results.push({ rule: 'maxRepeatedChars', passed: false, message: `Character repeated ${maxRepeat} times (max ${policy.maxRepeatedChars})` });
    passed = false;
  } else {
    results.push({ rule: 'maxRepeatedChars', passed: true, message: `Max character repetition: ${maxRepeat}` });
  }

  // Score check
  const { score } = calculateScore(password);
  if (score < policy.minScore) {
    results.push({ rule: 'minScore', passed: false, message: `Score ${score} is below minimum ${policy.minScore}` });
    passed = false;
  } else {
    results.push({ rule: 'minScore', passed: true, message: `Score ${score} >= ${policy.minScore}` });
  }

  // Custom blacklist
  if (policy.customBlacklist.length > 0) {
    const lower = password.toLowerCase();
    for (const word of policy.customBlacklist) {
      if (lower.includes(word.toLowerCase())) {
        results.push({ rule: 'customBlacklist', passed: false, message: `Contains blacklisted term: "${word}"` });
        passed = false;
      }
    }
    if (!results.find(r => r.rule === 'customBlacklist' && !r.passed)) {
      results.push({ rule: 'customBlacklist', passed: true, message: 'No blacklisted terms found' });
    }
  }

  return {
    passed,
    score,
    results,
    failedRules: results.filter(r => !r.passed).length,
    totalRules: results.length,
  };
}

function findMaxRepeat(password) {
  let max = 1;
  let current = 1;
  for (let i = 1; i < password.length; i++) {
    if (password[i] === password[i - 1]) {
      current++;
      max = Math.max(max, current);
    } else {
      current = 1;
    }
  }
  return max;
}

// ============================================================
// Breach check (SHA-1 prefix matching - HIBP compatible)
// ============================================================

function breachCheckInfo(password) {
  const sha1 = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
  const prefix = sha1.slice(0, 5);
  const suffix = sha1.slice(5);

  return {
    sha1Hash: sha1,
    prefix,
    suffix,
    apiUrl: `https://api.pwnedpasswords.com/range/${prefix}`,
    howToUse: [
      `1. Send GET request to: https://api.pwnedpasswords.com/range/${prefix}`,
      '2. The API returns a list of SHA-1 suffixes and breach counts',
      `3. Search the response for the suffix: ${suffix}`,
      '4. If found, the password has been seen in data breaches',
      '5. The number next to the suffix shows how many times it appeared',
    ],
    note: 'This uses k-anonymity: only the first 5 chars of the SHA-1 hash are sent to the API, so your full password is never exposed.',
    privacyGuarantee: 'The HaveIBeenPwned API uses a k-anonymity model. Your password never leaves this system — only a 5-character hash prefix is used for the API call.',
  };
}

module.exports = {
  analyzePassword,
  calculateScore,
  calculateEntropy,
  analyzeCharsets,
  detectPatterns,
  estimateCrackTime,
  validatePolicy,
  breachCheckInfo,
  isCommon,
  getRank,
};
