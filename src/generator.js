/**
 * Secure Password Generator
 * Generates random, pronounceable, and passphrase-style passwords
 */

const crypto = require('crypto');

// Character sets
const LOWER = 'abcdefghijklmnopqrstuvwxyz';
const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const DIGITS = '0123456789';
const SYMBOLS = '!@#$%^&*()_+-=[]{}|;:,.<>?';
const AMBIGUOUS = 'Il1O0oS5Z2';

// Pronounceable syllables
const CONSONANTS = ['b','c','d','f','g','h','j','k','l','m','n','p','qu','r','s','t','v','w','x','y','z',
  'bl','br','ch','cl','cr','dr','fl','fr','gl','gr','ph','pl','pr','sc','sh','sk','sl','sm','sn','sp',
  'st','str','sw','th','tr','tw','wh','wr'];
const VOWELS = ['a','e','i','o','u','ai','au','ea','ee','ei','ie','oa','oo','ou'];

// Common words for passphrases (732 words, all 4-8 letters, easy to type)
const WORDLIST = [
  'able','acid','aged','also','area','army','away','baby','back','ball','band','bank','base','bath',
  'beam','bear','beat','been','bell','belt','best','bill','bird','bite','blow','blue','boat','body',
  'bolt','bomb','bond','bone','book','boot','born','boss','both','bowl','bulk','burn','bush','busy',
  'cafe','cage','cake','call','calm','came','camp','card','care','cart','case','cash','cast','cave',
  'cell','chip','city','clad','clay','clip','club','clue','coal','coat','code','coil','cold','cole',
  'come','cook','cool','cope','copy','cord','core','corn','cost','crew','crop','cube','cult','cure',
  'dale','dame','dare','dark','data','date','dawn','dead','deaf','deal','dear','debt','deck','deep',
  'deer','desk','dial','dice','diet','dirt','disc','dish','dock','does','dome','done','door','dose',
  'down','draw','drew','drop','drug','drum','dual','duke','dull','dump','dune','dust','duty','each',
  'earn','ease','east','easy','edge','else','emit','epic','euro','even','ever','evil','exam','exec',
  'exit','eyed','face','fact','fade','fail','fair','fake','fall','fame','farm','fast','fate','fear',
  'feat','feed','feel','feet','fell','felt','file','fill','film','find','fine','fire','firm','fish',
  'five','flag','flat','fled','flew','flip','flow','foam','fold','folk','fond','font','fool','foot',
  'ford','fore','fork','form','fort','foul','four','free','from','fuel','full','fund','fury','fuse',
  'gain','gale','game','gang','gate','gave','gaze','gear','gene','gift','girl','give','glad','glow',
  'glue','goat','goes','gold','golf','gone','good','grab','gray','grew','grid','grin','grip','grow',
  'gulf','guru','hack','half','hall','halt','hand','hang','hard','harm','hate','haul','have','hawk',
  'head','heal','heap','hear','heat','heel','held','help','herb','here','hero','hide','high','hike',
  'hill','hint','hire','hold','hole','holy','home','hook','hope','horn','host','hour','huge','hull',
  'hung','hunt','hurt','icon','idea','inch','info','iron','isle','item','jack','jail','jazz','jean',
  'jest','jobs','join','joke','jump','jury','just','keen','keep','kent','kept','kick','kill','kind',
  'king','kiss','knee','knew','knit','knot','know','lack','lady','laid','lake','lamp','land','lane',
  'lash','last','late','lawn','lead','leaf','lean','left','lend','lens','lent','less','lick','lied',
  'lieu','life','lift','like','limb','lime','limp','line','link','lion','list','live','load','loan',
  'lock','logo','lone','long','look','lord','lose','loss','lost','loud','love','luck','lump','lung',
  'lure','lurk','made','mail','main','make','male','mall','malt','mane','many','mare','mark','mars',
  'mask','mass','mast','mate','maze','meal','mean','meat','meet','melt','memo','menu','mere','mesh',
  'mess','mice','mild','mile','milk','mill','mind','mine','mint','miss','mode','mold','mood','moon',
  'more','moss','most','moth','move','much','mule','muse','must','myth','nail','name','nave','navy',
  'near','neat','neck','need','nest','nets','news','next','nice','nine','node','none','noon','norm',
  'nose','note','noun','nova','nuts','oath','obey','odds','okay','once','only','onto','open','oral',
  'ours','oval','oven','over','owed','pace','pack','page','paid','pain','pair','pale','palm','pane',
  'park','part','pass','past','path','peak','peel','peer','pine','pink','pipe','plan','play','plea',
  'plot','ploy','plug','plus','poem','poet','pole','poll','polo','pond','pool','pope','pork','port',
  'pose','post','pour','pray','prey','prop','pull','pump','pure','push','quit','quiz','race','rack',
  'rage','raid','rail','rain','rank','rare','rate','read','real','rear','reef','rein','rely','rent',
  'rest','rice','rich','ride','rife','rift','ring','riot','rise','risk','road','roam','rock','rode',
  'role','roll','roof','room','root','rope','rose','ruin','rule','rush','rust','sack','safe','sage',
  'said','sail','sake','sale','salt','same','sand','sang','save','seal','seat','seed','seek','seem',
  'seen','self','sell','send','sent','sept','shed','ship','shock','shoe','shop','shot','show','shut',
  'sick','side','sigh','sign','silk','sing','sink','site','size','skip','slam','slid','slim','slip',
  'slot','slow','snap','snow','soap','soar','sock','soft','soil','sold','sole','some','song','soon',
  'sort','soul','spin','spot','star','stay','stem','step','stir','stop','stub','such','suit','sure',
  'surf','swan','swap','swim','tail','take','tale','talk','tall','tank','tape','task','taxi','team',
  'tear','tell','temp','tend','tent','term','test','text','than','that','them','then','they','thin',
  'this','thus','tide','tidy','tied','tier','till','time','tiny','tire','toil','told','toll','tomb',
  'tone','took','tool','tops','tore','torn','tour','town','trap','tray','tree','trek','trim','trio',
  'trip','true','tube','tuck','tune','turn','twin','type','ugly','unit','unto','upon','urge','used',
  'user','vain','vale','vary','vast','veil','vein','very','vice','view','vine','visa','void','volt',
  'vote','wade','wage','wait','wake','walk','wall','ward','warm','warn','wary','wash','vast','wave',
  'weak','wear','weed','week','well','went','were','west','what','when','whom','wide','wife','wild',
  'will','wind','wine','wing','wire','wise','wish','with','woke','wolf','wood','wool','word','wore',
  'work','worm','worn','wrap','yard','yeah','year','yell','your','zeal','zero','zinc','zone','zoom',
];

function secureRandom(max) {
  const bytes = crypto.randomBytes(4);
  return bytes.readUInt32BE(0) % max;
}

function shuffleArray(arr) {
  const result = [...arr];
  for (let i = result.length - 1; i > 0; i--) {
    const j = secureRandom(i + 1);
    [result[i], result[j]] = [result[j], result[i]];
  }
  return result;
}

/**
 * Generate a random password
 */
function generateRandom(options = {}) {
  const {
    length = 16,
    includeLowercase = true,
    includeUppercase = true,
    includeDigits = true,
    includeSymbols = true,
    excludeAmbiguous = false,
    customChars = '',
  } = options;

  let charset = '';
  const required = [];

  if (includeLowercase) {
    charset += LOWER;
    required.push(LOWER[secureRandom(LOWER.length)]);
  }
  if (includeUppercase) {
    charset += UPPER;
    required.push(UPPER[secureRandom(UPPER.length)]);
  }
  if (includeDigits) {
    charset += DIGITS;
    required.push(DIGITS[secureRandom(DIGITS.length)]);
  }
  if (includeSymbols) {
    charset += SYMBOLS;
    required.push(SYMBOLS[secureRandom(SYMBOLS.length)]);
  }
  if (customChars) {
    charset += customChars;
  }

  if (excludeAmbiguous) {
    charset = charset.split('').filter(c => !AMBIGUOUS.includes(c)).join('');
  }

  if (charset.length === 0) {
    charset = LOWER + UPPER + DIGITS;
    required.push(LOWER[secureRandom(LOWER.length)]);
  }

  const actualLength = Math.max(length, required.length);

  // Fill remaining with random chars
  const remaining = actualLength - required.length;
  const chars = [...required];
  for (let i = 0; i < remaining; i++) {
    chars.push(charset[secureRandom(charset.length)]);
  }

  // Shuffle to avoid predictable positions
  return shuffleArray(chars).join('');
}

/**
 * Generate a pronounceable password
 */
function generatePronounceable(options = {}) {
  const { length = 14, includeDigits = true, includeSymbols = false, capitalize = true } = options;

  let password = '';
  let syllableCount = 0;

  while (password.length < length) {
    const consonant = CONSONANTS[secureRandom(CONSONANTS.length)];
    const vowel = VOWELS[secureRandom(VOWELS.length)];

    if (capitalize && syllableCount % 2 === 0 && secureRandom(3) === 0) {
      password += consonant.charAt(0).toUpperCase() + consonant.slice(1);
    } else {
      password += consonant;
    }
    password += vowel;
    syllableCount++;

    // Occasionally add an ending consonant
    if (secureRandom(3) === 0 && password.length < length - 2) {
      password += 'nstrlm'[secureRandom(6)];
    }
  }

  password = password.slice(0, length);

  // Add digit/symbol suffix if requested
  if (includeDigits) {
    const digit = DIGITS[secureRandom(DIGITS.length)];
    password = password.slice(0, -1) + digit;
  }
  if (includeSymbols) {
    const sym = '!@#$%&*'[secureRandom(7)];
    password = password.slice(0, -1) + sym;
  }

  return password;
}

/**
 * Generate a passphrase (diceware-style)
 */
function generatePassphrase(options = {}) {
  const {
    words = 5,
    separator = '-',
    capitalize = true,
    includeNumber = true,
  } = options;

  const chosen = [];
  const usedIndices = new Set();

  while (chosen.length < words) {
    const idx = secureRandom(WORDLIST.length);
    if (usedIndices.has(idx)) continue;
    usedIndices.add(idx);
    let word = WORDLIST[idx];
    if (capitalize) word = word.charAt(0).toUpperCase() + word.slice(1);
    chosen.push(word);
  }

  let passphrase = chosen.join(separator);

  if (includeNumber) {
    const num = secureRandom(100);
    passphrase += separator + num.toString().padStart(2, '0');
  }

  return passphrase;
}

/**
 * Generate a PIN
 */
function generatePin(options = {}) {
  const { length = 6 } = options;
  let pin = '';
  for (let i = 0; i < length; i++) {
    pin += DIGITS[secureRandom(DIGITS.length)];
  }
  return pin;
}

/**
 * Main generation function
 */
function generate(options = {}) {
  const { type = 'random', count = 1, ...rest } = options;

  const results = [];
  for (let i = 0; i < Math.min(count, 50); i++) {
    let password;
    switch (type) {
      case 'pronounceable':
        password = generatePronounceable(rest);
        break;
      case 'passphrase':
        password = generatePassphrase(rest);
        break;
      case 'pin':
        password = generatePin(rest);
        break;
      case 'random':
      default:
        password = generateRandom(rest);
        break;
    }
    results.push(password);
  }

  return count === 1 ? results[0] : results;
}

module.exports = { generate, generateRandom, generatePronounceable, generatePassphrase, generatePin };
