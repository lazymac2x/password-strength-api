const { Actor } = require('apify');
const { analyzePassword, validatePolicy, breachCheckInfo, isCommon, getRank } = require('./analyzer');
const { generate } = require('./generator');

Actor.main(async () => {
  const input = await Actor.getInput();
  const {
    action = 'analyze',
    password,
    passwords,
    policy,
    generateOptions,
  } = input || {};

  let result;

  switch (action) {
    case 'analyze': {
      if (!password) throw new Error('password is required for analyze action');
      result = analyzePassword(password);
      console.log(`Analyzed password: score=${result.score}, strength=${result.strength}`);
      break;
    }
    case 'check_common': {
      if (!password) throw new Error('password is required for check_common action');
      const common = isCommon(password);
      const rank = getRank(password);
      result = { isCommon: common, rank };
      console.log(`Common check: ${common ? `YES (rank #${rank})` : 'NOT common'}`);
      break;
    }
    case 'validate': {
      if (!password) throw new Error('password is required for validate action');
      result = validatePolicy(password, policy || {});
      console.log(`Policy validation: ${result.passed ? 'PASSED' : 'FAILED'} (${result.failedRules} failed rules)`);
      break;
    }
    case 'generate': {
      const opts = generateOptions || {};
      const generated = generate(opts);
      if (typeof generated === 'string') {
        result = { password: generated, analysis: analyzePassword(generated) };
      } else {
        result = { passwords: generated, count: generated.length };
      }
      console.log(`Generated ${typeof generated === 'string' ? '1' : generated.length} password(s)`);
      break;
    }
    case 'breach_check': {
      if (!password) throw new Error('password is required for breach_check action');
      result = breachCheckInfo(password);
      console.log(`Breach check info generated for password (SHA-1 prefix: ${result.prefix})`);
      break;
    }
    case 'batch': {
      if (!Array.isArray(passwords) || passwords.length === 0) {
        throw new Error('passwords array is required for batch action');
      }
      const limited = passwords.slice(0, 100);
      const results = limited.map(pw => analyzePassword(pw));
      result = {
        count: results.length,
        averageScore: Math.round(results.reduce((s, r) => s + (r.score || 0), 0) / results.length),
        results,
      };
      console.log(`Batch analyzed ${results.length} passwords, avg score: ${result.averageScore}`);
      break;
    }
    default:
      throw new Error(`Unknown action: ${action}. Valid: analyze, check_common, validate, generate, breach_check, batch`);
  }

  await Actor.pushData({ action, ...result });
  console.log('Done.');
});
