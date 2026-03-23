# Password Strength Analyzer

Comprehensive password strength analysis tool.

## Features
- **Strength Scoring** — 0-100 score based on entropy, length, charset diversity
- **Crack Time Estimation** — Time to crack across 6 attack scenarios (online throttled to state-level)
- **Pattern Detection** — Keyboard walks, sequences, repeated chars, dates, common words, leet speak
- **Common Password Check** — Against top 10,000 most common passwords
- **Policy Validation** — Configurable rules (length, charset, patterns, blacklist)
- **Password Generation** — Random, pronounceable, passphrase, PIN
- **Breach Check** — SHA-1 k-anonymity pattern for HaveIBeenPwned API
- **Batch Analysis** — Up to 100 passwords at once

## Actions

### analyze
Analyze a single password. Returns score, entropy, crack times, patterns, suggestions.

### check_common
Check if password is in top 10K common passwords list.

### validate
Validate password against a configurable policy.

### generate
Generate secure passwords (random, pronounceable, passphrase, PIN).

### breach_check
Get SHA-1 hash info for checking against HaveIBeenPwned API.

### batch
Analyze multiple passwords at once with summary statistics.
