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
  const fullUrl = url.toLowerCase();

  if (parsedUrl.protocol === 'http:') {
    score += 10;
    reasons.push('The website uses HTTP instead of HTTPS.');
  }

  if (isIpAddress(hostname)) {
    score += 25;
    reasons.push('The website uses an IP address instead of a domain name.');
  }

  if (hostname.includes('xn--')) {
    score += 20;
    reasons.push(
      'The domain contains punycode, which can be used for lookalike domains.',
    );
  }

  if (url.includes('@')) {
    score += 20;
    reasons.push(
      'The URL contains @, which can be used to disguise the actual destination.',
    );
  }

  if (url.length > 150) {
    score += 15;
    reasons.push('The URL is unusually long.');
  }

  const encodedCharacters = (url.match(/%[0-9a-f]{2}/gi) || []).length;

  if (encodedCharacters >= 5) {
    score += 10;
    reasons.push('The URL contains a high amount of encoded characters.');
  }

  const subdomainCount = hostname.split('.').length - 2;

  if (subdomainCount >= 3) {
    score += 10;
    reasons.push(
      'The domain contains an unusually high number of subdomains.',
    );
  }

  const parts = hostname.split('.');
  const tld = parts[parts.length - 1];

  if (SUSPICIOUS_TLDS.has(tld)) {
    score += 15;
    reasons.push(
      `The domain uses a potentially suspicious top-level domain (.${tld}).`,
    );
  }

  const matchedKeywords = SUSPICIOUS_KEYWORDS.filter((keyword) =>
    fullUrl.includes(keyword),
  );

  if (matchedKeywords.length > 0) {
    score += Math.min(matchedKeywords.length * 5, 20);

    reasons.push(
      `The URL contains security-sensitive keywords: ${matchedKeywords.join(', ')}.`,
    );
  }

  if (
    parsedUrl.port &&
    !['80', '443', '8080', '8443'].includes(parsedUrl.port)
  ) {
    score += 10;
    reasons.push(`The website uses an unusual port (${parsedUrl.port}).`);
  }

  score = Math.min(score, 100);

  return {
    url,
    score,
    level: getRiskLevel(score),
    reasons,
  };
}
