export type RiskLevel = 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface UrlAnalysis {
  url: string;
  score: number;
  level: RiskLevel;
  reasons: string[];
}

const SUSPICIOUS_TLDS = new Set([
  'zip',
  'mov',
  'top',
  'xyz',
  'click',
  'loan',
  'download',
  'work',
  'gq',
  'tk',
  'ml',
  'cf',
  'ga',
]);

const SUSPICIOUS_KEYWORDS = [
  'login',
  'signin',
  'verify',
  'verification',
  'account',
  'secure',
  'security',
  'password',
  'credential',
  'authenticate',
  'payment',
  'billing',
  'confirm',
  'update',
  'wallet',
];

const SUSPICIOUS_KEYWORD_COMBINATIONS = [
  ['login', 'verify'],
  ['login', 'account'],
  ['login', 'secure'],
  ['signin', 'verify'],
  ['signin', 'account'],
  ['verify', 'account'],
  ['verify', 'security'],
  ['secure', 'account'],
  ['secure', 'login'],
  ['password', 'verify'],
  ['credential', 'verify'],
  ['payment', 'verify'],
  ['billing', 'update'],
  ['wallet', 'connect'],
  ['account', 'confirm'],
];

function isIpAddress(hostname: string): boolean {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
}

function getRiskLevel(score: number): RiskLevel {
  if (score >= 75) return 'CRITICAL';
  if (score >= 50) return 'HIGH';
  if (score >= 25) return 'MEDIUM';
  if (score > 0) return 'LOW';
  return 'SAFE';
}

export function analyzeUrl(url: string): UrlAnalysis {
  let score = 0;
  const reasons: string[] = [];

  let parsedUrl: URL;

  try {
    parsedUrl = new URL(url);
  } catch {
    return {
      url,
      score: 100,
      level: 'CRITICAL',
      reasons: ['The URL could not be parsed safely.'],
    };
  }

  const hostname = parsedUrl.hostname.toLowerCase();
  const pathname = parsedUrl.pathname.toLowerCase();
  const fullUrl = url.toLowerCase();

  // HTTP instead of HTTPS
  if (parsedUrl.protocol === 'http:') {
    score += 10;
    reasons.push('The website uses HTTP instead of HTTPS.');
  }

  // IP address instead of a domain name
  if (isIpAddress(hostname)) {
    score += 25;
    reasons.push('The website uses an IP address instead of a domain name.');
  }

  // Punycode domains
  if (hostname.includes('xn--')) {
    score += 20;
    reasons.push(
      'The domain contains punycode, which can be used for lookalike domains.',
    );
  }

  // Credentials / userinfo before the hostname
  if (parsedUrl.username || parsedUrl.password) {
    score += 30;
    reasons.push(
      'The URL contains embedded credentials, which can be used to disguise the actual destination.',
    );
  } else if (url.includes('@')) {
    score += 20;
    reasons.push(
      'The URL contains @, which can be used to disguise the actual destination.',
    );
  }

  // Very long URLs
  if (url.length > 150) {
    score += 15;
    reasons.push('The URL is unusually long.');
  }

  // Excessive URL encoding
  const encodedCharacters = (url.match(/%[0-9a-f]{2}/gi) || []).length;

  if (encodedCharacters >= 5) {
    score += 10;
    reasons.push('The URL contains a high amount of encoded characters.');
  }

  // Excessive subdomains
  const hostnameParts = hostname.split('.');
  const subdomainCount = Math.max(hostnameParts.length - 2, 0);

  if (subdomainCount >= 3) {
    score += 10;
    reasons.push(
      'The domain contains an unusually high number of subdomains.',
    );
  }

  // Hyphen-heavy hostname
  const hyphenCount = (hostname.match(/-/g) || []).length;

  if (hyphenCount >= 3) {
    score += 15;
    reasons.push(
      'The hostname contains an unusually high number of hyphens.',
    );
  }

  // Numeric-heavy hostname
  const hostnameDigits = (hostname.match(/\d/g) || []).length;
  const hostnameLetters = (hostname.match(/[a-z]/g) || []).length;

  if (
    hostnameDigits >= 4 &&
    hostnameDigits >= hostnameLetters &&
    hostname.length >= 8
  ) {
    score += 15;
    reasons.push(
      'The hostname contains an unusually high amount of numeric characters.',
    );
  }

  // Unusually long hostname
  if (hostname.length > 50) {
    score += 15;
    reasons.push('The hostname is unusually long.');
  }

  // Suspicious top-level domain
  const tld = hostnameParts[hostnameParts.length - 1];

  if (SUSPICIOUS_TLDS.has(tld)) {
    score += 15;
    reasons.push(
      `The domain uses a potentially suspicious top-level domain (.${tld}).`,
    );
  }

  // Suspicious words
  const matchedKeywords = SUSPICIOUS_KEYWORDS.filter((keyword) =>
    fullUrl.includes(keyword),
  );

  if (matchedKeywords.length > 0) {
    score += Math.min(matchedKeywords.length * 5, 25);

    reasons.push(
      `The URL contains security-sensitive keywords: ${matchedKeywords.join(', ')}.`,
    );
  }

  // Suspicious keyword combinations
  const matchedCombinations = SUSPICIOUS_KEYWORD_COMBINATIONS.filter(
    ([first, second]) =>
      fullUrl.includes(first) && fullUrl.includes(second),
  );

  if (matchedCombinations.length > 0) {
    score += Math.min(matchedCombinations.length * 10, 30);

    const combinationNames = matchedCombinations.map(
      ([first, second]) => `${first} + ${second}`,
    );

    reasons.push(
      `The URL contains suspicious keyword combinations: ${combinationNames.join(', ')}.`,
    );
  }

  // Double extensions such as .pdf.exe, .jpg.scr, .doc.zip
  const dangerousDoubleExtensionPattern =
    /\.(pdf|doc|docx|xls|xlsx|jpg|jpeg|png|txt|zip|rar)\.(exe|scr|bat|cmd|com|js|vbs|msi|dll)$/i;

  if (dangerousDoubleExtensionPattern.test(pathname)) {
    score += 30;
    reasons.push(
      'The URL contains a suspicious double file extension that may disguise an executable file.',
    );
  }

  // More general executable extension disguised after another extension
  const disguisedExecutablePattern =
    /\.[a-z0-9]{1,8}\.(exe|scr|bat|cmd|com|js|vbs|msi|dll)$/i;

  if (
    disguisedExecutablePattern.test(pathname) &&
    !dangerousDoubleExtensionPattern.test(pathname)
  ) {
    score += 20;
    reasons.push(
      'The URL ends with an executable file extension after another file extension.',
    );
  }

  // Unusual port
  if (
    parsedUrl.port &&
    !['80', '443', '8080', '8443'].includes(parsedUrl.port)
  ) {
    score += 10;
    reasons.push(`The website uses an unusual port (${parsedUrl.port}).`);
  }

  // Multiple independent suspicious signals increase confidence.
  const signalCount = [
    isIpAddress(hostname),
    hostname.includes('xn--'),
    Boolean(parsedUrl.username || parsedUrl.password),
    url.includes('@'),
    url.length > 150,
    encodedCharacters >= 5,
    subdomainCount >= 3,
    hyphenCount >= 3,
    hostnameDigits >= 4 &&
      hostnameDigits >= hostnameLetters &&
      hostname.length >= 8,
    hostname.length > 50,
    SUSPICIOUS_TLDS.has(tld),
    matchedKeywords.length > 0,
    matchedCombinations.length > 0,
    dangerousDoubleExtensionPattern.test(pathname),
    disguisedExecutablePattern.test(pathname),
    Boolean(
      parsedUrl.port &&
        !['80', '443', '8080', '8443'].includes(parsedUrl.port),
    ),
  ].filter(Boolean).length;

  if (signalCount >= 4) {
    score += 15;
    reasons.push(
      'Multiple independent suspicious URL signals were detected.',
    );
  } else if (signalCount >= 3) {
    score += 10;
    reasons.push(
      'Several independent suspicious URL signals were detected.',
    );
  }

  score = Math.min(score, 100);

  return {
    url,
    score,
    level: getRiskLevel(score),
    reasons,
  };
}