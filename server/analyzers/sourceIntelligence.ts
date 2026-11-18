import * as cheerio from 'cheerio';
import type {
  CheckFinding,
  FormSecurityDetail,
  SourceIntelligenceData,
  SupplyChainResourceSummary,
  SuspiciousCodeSignal,
} from '../types.ts';
import { classifyDomainRelationship } from './officialDomainRegistry.ts';
import { extractRegistrableDomain } from './urlIntelligence.ts';

const KNOWN_CDN_DOMAINS = new Set([
  'cdnjs.cloudflare.com',
  'cdn.jsdelivr.net',
  'unpkg.com',
  'ajax.googleapis.com',
  'code.jquery.com',
  'stackpath.bootstrapcdn.com',
  'maxcdn.bootstrapcdn.com',
  'cdn.tailwindcss.com',
  'fonts.googleapis.com',
  'fonts.gstatic.com',
]);

const KNOWN_TRACKERS = [
  { name: 'Google Analytics / GTM', pattern: /googletagmanager\.com|google-analytics\.com|ga\.js|gtag/i },
  { name: 'Meta Pixel', pattern: /connect\.facebook\.net|fbevents\.js/i },
  { name: 'Hotjar', pattern: /hotjar\.com/i },
  { name: 'Mixpanel', pattern: /mixpanel\.com/i },
  { name: 'Sentry', pattern: /sentry\.io|browser\.sentry-cdn\.com/i },
  { name: 'Cloudflare Insights', pattern: /static\.cloudflareinsights\.com/i },
];

const VULNERABLE_LIB_PATTERNS = [
  { library: 'jQuery', pattern: /jquery[.-](\d+\.\d+\.\d+)/i, maxSafe: '3.5.0', advisory: 'jQuery <3.5.0 is vulnerable to XSS in HTML parsing.' },
  { library: 'Bootstrap JS', pattern: /bootstrap[.-](\d+\.\d+\.\d+)/i, maxSafe: '4.3.1', advisory: 'Bootstrap <4.3.1 has XSS vulnerabilities in tooltip/popover data attributes.' },
  { library: 'AngularJS', pattern: /angular[.-](\d+\.\d+\.\d+)/i, maxSafe: '1.8.0', advisory: 'AngularJS 1.x has multiple prototype pollution and template injection vectors.' },
  { library: 'Lodash', pattern: /lodash[.-](\d+\.\d+\.\d+)/i, maxSafe: '4.17.21', advisory: 'Lodash <4.17.21 is vulnerable to prototype pollution and regular expression denial of service.' },
];

export function analyzeSourceIntelligence(
  finalUrl: string,
  headers: Record<string, string>,
  htmlBuffer?: Buffer
): {
  sourceIntel: SourceIntelligenceData;
  formDetails: FormSecurityDetail[];
  supplyChain: SupplyChainResourceSummary;
  findings: CheckFinding[];
} {
  const now = new Date().toISOString();
  const findings: CheckFinding[] = [];

  const parsedUrl = new URL(finalUrl);
  const finalHost = parsedUrl.hostname.toLowerCase();
  const finalRegDomain = extractRegistrableDomain(finalHost);

  const securityHeaders = {
    csp: headers['content-security-policy'],
    hsts: headers['strict-transport-security'],
    xFrameOptions: headers['x-frame-options'],
    xContentTypeOptions: headers['x-content-type-options'],
    referrerPolicy: headers['referrer-policy'],
    permissionsPolicy: headers['permissions-policy'],
  };

  if (!htmlBuffer) {
    const emptySource: SourceIntelligenceData = {
      ogTags: {},
      jsonLdCount: 0,
      jsonLdTypes: [],
      baseTagHijack: false,
      securityHeaders,
      externalJsFiles: [],
      externalCssFiles: [],
      inlineJsCount: 0,
      inlineCssCount: 0,
      iframeSources: [],
      embeddedResources: [],
      hiddenInputs: [],
      suspiciousAttributes: [],
      suspiciousCodeSignals: [],
      lureExcerpts: [],
    };
    const emptySupplyChain: SupplyChainResourceSummary = {
      totalExternalDomains: 0,
      scripts: [],
      stylesheets: [],
      iframes: [],
      fonts: [],
      imagesCount: 0,
      externalImagesCount: 0,
      apiEndpoints: [],
      trackingServices: [],
      cdnDomains: [],
      externalForms: [],
      outdatedLibraries: [],
    };
    return { sourceIntel: emptySource, formDetails: [], supplyChain: emptySupplyChain, findings };
  }

  const html = htmlBuffer.toString('utf8');
  const $ = cheerio.load(html);

  // 1. Meta Tags & Canonical
  const canonicalUrl = $('link[rel="canonical"]').attr('href')?.trim();
  const ogTags: Record<string, string> = {};
  $('meta[property^="og:"], meta[name^="og:"]').each((_, el) => {
    const prop = ($(el).attr('property') || $(el).attr('name') || '').trim();
    const content = ($(el).attr('content') || '').trim();
    if (prop) ogTags[prop] = content;
  });

  const jsonLdTypes: string[] = [];
  let jsonLdCount = 0;
  $('script[type="application/ld+json"]').each((_, el) => {
    jsonLdCount++;
    try {
      const parsed = JSON.parse($(el).html() || '{}');
      if (parsed['@type']) {
        const t = Array.isArray(parsed['@type']) ? parsed['@type'].join(', ') : String(parsed['@type']);
        jsonLdTypes.push(t);
      }
    } catch {
      // ignore
    }
  });

  // 2. Base Tag Hijacking (ignore benign same-company/authorized domains)
  const baseTagHref = $('base').attr('href')?.trim();
  let baseTagHijack = false;
  if (baseTagHref) {
    try {
      const resolvedBase = new URL(baseTagHref, finalUrl);
      const baseReg = extractRegistrableDomain(resolvedBase.hostname);
      const rel = classifyDomainRelationship(finalHost, resolvedBase.hostname);
      if (baseReg !== finalRegDomain && !rel.isBenignOrAuthorized) {
        baseTagHijack = true;
      }
    } catch {
      baseTagHijack = true;
    }
  }

  const metaRefresh = $('meta[http-equiv="refresh" i]').attr('content')?.trim();

  // 3. External & Inline Resources
  const externalJsFiles: string[] = [];
  const externalCssFiles: string[] = [];
  let inlineJsCount = 0;
  let inlineCssCount = 0;
  const iframeSources: string[] = [];
  const embeddedResources: { tag: string; src: string }[] = [];
  const externalDomainsSet = new Set<string>();

  const scriptList: { url: string; host: string; isThirdParty: boolean; isCdn: boolean }[] = [];
  const stylesheetList: { url: string; host: string; isThirdParty: boolean; isCdn: boolean }[] = [];
  const iframeList: { url: string; host: string; isThirdParty: boolean }[] = [];
  const fontList: string[] = [];
  const apiEndpointsSet = new Set<string>();

  $('script[src]').each((_, el) => {
    const src = ($(el).attr('src') || '').trim();
    if (src) {
      externalJsFiles.push(src.slice(0, 160));
      try {
        const u = new URL(src, finalUrl);
        const host = u.hostname.toLowerCase();
        const reg = extractRegistrableDomain(host);
        const isTP = reg !== finalRegDomain;
        const isCdn = KNOWN_CDN_DOMAINS.has(host) || KNOWN_CDN_DOMAINS.has(reg);
        if (isTP) externalDomainsSet.add(host);
        scriptList.push({ url: u.toString(), host, isThirdParty: isTP, isCdn });
      } catch {
        // ignore
      }
    }
  });

  $('script:not([src])').each((_, el) => {
    inlineJsCount++;
    const code = $(el).html() || '';
    // Extract static API endpoints from JS code strings
    const urlMatches = code.match(/https?:\/\/[a-z0-9.-]+\.[a-z]{2,20}(?:\/[^\s"'<>]+)?/gi) || [];
    for (const m of urlMatches) {
      if (apiEndpointsSet.size < 20) apiEndpointsSet.add(m.slice(0, 120));
    }
  });

  $('link[rel="stylesheet"]').each((_, el) => {
    const href = ($(el).attr('href') || '').trim();
    if (href) {
      externalCssFiles.push(href.slice(0, 160));
      try {
        const u = new URL(href, finalUrl);
        const host = u.hostname.toLowerCase();
        const reg = extractRegistrableDomain(host);
        const isTP = reg !== finalRegDomain;
        const isCdn = KNOWN_CDN_DOMAINS.has(host);
        if (isTP) externalDomainsSet.add(host);
        stylesheetList.push({ url: u.toString(), host, isThirdParty: isTP, isCdn });
      } catch {
        // ignore
      }
    }
  });

  $('style').each(() => {
    inlineCssCount++;
  });

  $('iframe[src]').each((_, el) => {
    const src = ($(el).attr('src') || '').trim();
    if (src) {
      iframeSources.push(src.slice(0, 160));
      try {
        const u = new URL(src, finalUrl);
        const host = u.hostname.toLowerCase();
        const isTP = extractRegistrableDomain(host) !== finalRegDomain;
        iframeList.push({ url: u.toString(), host, isThirdParty: isTP });
      } catch {
        // ignore
      }
    }
  });

  $('[data-font], link[rel*="font"], @import').each((_, el) => {
    const href = $(el).attr('href') || $(el).attr('src') || '';
    if (/fonts\./i.test(href) || /\.woff2?/i.test(href)) {
      fontList.push(href.slice(0, 100));
    }
  });

  $('object, embed, svg').each((_, el) => {
    const src = $(el).attr('data') || $(el).attr('src') || '';
    embeddedResources.push({ tag: el.tagName.toLowerCase(), src: src.slice(0, 120) });
  });

  let imagesCount = 0;
  let externalImagesCount = 0;
  $('img[src]').each((_, el) => {
    imagesCount++;
    const src = ($(el).attr('src') || '').trim();
    if (/^https?:\/\//i.test(src)) {
      try {
        if (extractRegistrableDomain(new URL(src).hostname) !== finalRegDomain) {
          externalImagesCount++;
        }
      } catch {
        // ignore
      }
    }
  });

  // 4. Hidden Inputs & Suspicious Attributes
  const hiddenInputs: { name?: string; type: string; valuePreview?: string }[] = [];
  $('input[type="hidden"]').each((_, el) => {
    const name = $(el).attr('name') || $(el).attr('id');
    const val = $(el).attr('value') || '';
    hiddenInputs.push({ name, type: 'hidden', valuePreview: val.slice(0, 40) });
  });

  const suspiciousAttributes: { attribute: string; tag: string; snippet: string }[] = [];
  $('*').each((_, el) => {
    const node = el as any;
    const tag = (node.tagName || 'element').toLowerCase();
    for (const attr of node.attribs ? Object.keys(node.attribs) : []) {
      const val = node.attribs[attr] || '';
      if (
        /^on[a-z]+/i.test(attr) ||
        /javascript:|data:text\/html/i.test(val) ||
        (attr === 'formaction' && /^https?:\/\//i.test(val))
      ) {
        suspiciousAttributes.push({ attribute: attr, tag, snippet: `${attr}="${val.slice(0, 60)}"` });
      }
    }
  });

  // 5. Context-Aware Static JS Code Signals
  const suspiciousCodeSignals: SuspiciousCodeSignal[] = [];
  const fullHtmlText = html.slice(0, 100000);

  if (/eval\s*\(/i.test(fullHtmlText)) {
    suspiciousCodeSignals.push({
      id: 'js-eval',
      indicator: 'eval() usage',
      category: 'dynamic_eval',
      codeExcerpt: 'eval(...) detected in script blocks',
      contextAssessment: {
        en: 'eval() is used to execute string code dynamically. In standard marketing sites this may be part of bundling libraries, but in login flows it can cloak obfuscated credential exfiltration.',
        ar: 'يُستخدم eval() لتنفيذ الأكواد ديناميكياً؛ قد يكون جزءاً من مكتبات معتادة أو لإخفاء عمليات سرقة بيانات.',
      },
      benignContextPossible: true,
      riskLevel: 'medium',
    });
  }

  if (/atob\s*\(|btoa\s*\(/i.test(fullHtmlText)) {
    suspiciousCodeSignals.push({
      id: 'js-base64',
      indicator: 'Base64 string decoding (atob)',
      category: 'obfuscation',
      codeExcerpt: 'atob() / btoa() encoding functions present',
      contextAssessment: {
        en: 'Base64 functions decode strings at runtime. Common in web apps for client-side state, but also used by phishing kits to conceal exfiltration URLs.',
        ar: 'تفك شفرة Base64 النصوص أثناء التشغيل؛ شائعة في التطبيقات الحديثة ولكنها تُستخدم أيضاً لإخفاء روابط الإرسال في التصيد.',
      },
      benignContextPossible: true,
      riskLevel: 'low',
    });
  }

  if (/document\.write\s*\(/i.test(fullHtmlText)) {
    suspiciousCodeSignals.push({
      id: 'js-docwrite',
      indicator: 'document.write() injection',
      category: 'dom_injection',
      codeExcerpt: 'document.write(...) used in script',
      contextAssessment: {
        en: 'document.write() can overwrite DOM content during page load. Legacy analytics use this, but modern security guidelines discourage it due to DOM-based injection risks.',
        ar: 'يستطيع document.write كتابة محتوى في الصفحة مباشرة أثناء التحميل؛ وهي تقنية قديمة تتجنبها الممارسات الأمنية الحديثة.',
      },
      benignContextPossible: true,
      riskLevel: 'medium',
    });
  }

  // 6. Detailed Per-Form Analysis (FormSecurityDetail[])
  const formDetails: FormSecurityDetail[] = [];
  $('form').each((idx, el) => {
    const action = ($(el).attr('action') || '').trim();
    const method = ($(el).attr('method') || 'GET').toUpperCase();
    const idOrName = $(el).attr('id') || $(el).attr('name');
    let resolvedHost = finalHost;
    let isCrossOrigin = false;
    let originMismatch = false;

    if (action) {
      try {
        const u = new URL(action, finalUrl);
        resolvedHost = u.hostname.toLowerCase();
        const rel = classifyDomainRelationship(finalHost, resolvedHost);
        isCrossOrigin = extractRegistrableDomain(resolvedHost) !== finalRegDomain && !rel.isBenignOrAuthorized;
        originMismatch = isCrossOrigin;
      } catch {
        // relative action
      }
    }

    const inputTypesSet = new Set<string>();
    let pwdCount = 0;
    let emailCount = 0;
    let otpCount = 0;
    let pinCount = 0;
    let cardCount = 0;
    let hiddenCount = 0;
    let invisibleCount = 0;
    const unusualAttrs: string[] = [];
    const jsHandlers: string[] = [];

    $(el)
      .find('input, select, textarea')
      .each((_, inputEl) => {
        const t = ($(inputEl).attr('type') || 'text').toLowerCase();
        inputTypesSet.add(t);
        const nameId = ($(inputEl).attr('name') || $(inputEl).attr('id') || '').toLowerCase();
        const style = ($(inputEl).attr('style') || '').toLowerCase();

        if (t === 'hidden') {
          hiddenCount++;
        } else if (t === 'password') {
          pwdCount++;
        } else if (t === 'email' || /(?:^|[^a-z])(email|user|login)(?:$|[^a-z])/.test(nameId)) {
          emailCount++;
        } else if (/(?:^|[^a-z])(otp|2fa|pin[-_ ]?code)(?:$|[^a-z])/.test(nameId)) {
          otpCount++;
        } else if (/(?:^|[^a-z])(card[-_ ]?num|cvv|cvc|ccnum)(?:$|[^a-z])/.test(nameId)) {
          cardCount++;
        }

        if (/display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0\b/.test(style)) {
          invisibleCount++;
        }

        for (const attr of inputEl.attribs ? Object.keys(inputEl.attribs) : []) {
          if (/^on[a-z]+/i.test(attr)) jsHandlers.push(attr);
        }
      });

    let formRisk: FormSecurityDetail['riskLevel'] = 'informational';
    const reasonEn: string[] = [];
    const reasonAr: string[] = [];

    if (isCrossOrigin && pwdCount > 0) {
      formRisk = 'critical';
      reasonEn.push('Password form submits to an external cross-origin domain.');
      reasonAr.push('نموذج كلمة المرور يرسل البيانات إلى نطاق خارجي مختلف.');
    } else if (pwdCount > 0 && !action) {
      formRisk = 'high';
      reasonEn.push('Password form has no action attribute specified.');
      reasonAr.push('نموذج كلمة المرور لا يحدد وجهة الإرسال action.');
    } else if (pwdCount > 0) {
      formRisk = 'medium';
      reasonEn.push('Form requests password credentials.');
      reasonAr.push('النموذج يطلب بيانات تسجيل الدخول.');
    }

    formDetails.push({
      pageUrl: finalUrl,
      formIndex: idx + 1,
      idOrName,
      action: action || '[empty / current page]',
      resolvedActionHost: resolvedHost,
      method,
      usesHttps: finalUrl.startsWith('https://'),
      isCrossOrigin,
      originMismatch,
      inputTypes: Array.from(inputTypesSet),
      passwordCount: pwdCount,
      emailCount,
      otpCount,
      pinCount,
      cardCount,
      hiddenCount,
      invisibleCount,
      unusualAttributes: unusualAttrs,
      jsHandlers,
      riskLevel: formRisk,
      reason: {
        en: reasonEn.join(' ') || 'Standard form structure.',
        ar: reasonAr.join(' ') || 'بنية نموذج قياسية.',
      },
    });
  });

  // 7. Supply Chain Analysis & Outdated Libraries
  const trackingServices: { name: string; host: string }[] = [];
  for (const trk of KNOWN_TRACKERS) {
    for (const sc of scriptList) {
      if (trk.pattern.test(sc.url)) {
        if (!trackingServices.some((t) => t.name === trk.name)) {
          trackingServices.push({ name: trk.name, host: sc.host });
        }
      }
    }
  }

  const cdnDomains = Array.from(externalDomainsSet).filter((d) => KNOWN_CDN_DOMAINS.has(d));
  const outdatedLibraries: { library: string; detectedVersion: string; sourceUrl: string; advisory: string }[] = [];

  for (const sc of scriptList) {
    for (const libDef of VULNERABLE_LIB_PATTERNS) {
      const match = sc.url.match(libDef.pattern);
      if (match?.[1]) {
        outdatedLibraries.push({
          library: libDef.library,
          detectedVersion: match[1],
          sourceUrl: sc.url,
          advisory: libDef.advisory,
        });
      }
    }
  }

  const supplyChain: SupplyChainResourceSummary = {
    totalExternalDomains: externalDomainsSet.size,
    scripts: scriptList,
    stylesheets: stylesheetList,
    iframes: iframeList,
    fonts: fontList,
    imagesCount,
    externalImagesCount,
    apiEndpoints: Array.from(apiEndpointsSet),
    trackingServices,
    cdnDomains,
    externalForms: formDetails.filter((f) => f.isCrossOrigin).map((f) => f.action),
    outdatedLibraries,
  };

  const sourceIntel: SourceIntelligenceData = {
    canonicalUrl,
    ogTags,
    jsonLdCount,
    jsonLdTypes,
    baseTagHref,
    baseTagHijack,
    metaRefresh,
    securityHeaders,
    externalJsFiles,
    externalCssFiles,
    inlineJsCount,
    inlineCssCount,
    iframeSources,
    embeddedResources,
    hiddenInputs,
    suspiciousAttributes,
    suspiciousCodeSignals,
    lureExcerpts: [],
  };

  // Findings generation for Source Intelligence
  if (baseTagHijack) {
    findings.push({
      id: 'source-base-tag-hijack',
      section: 'source_intelligence',
      test: { en: 'Base HTML Tag Hijack Check', ar: 'فحص التلاعب بوسم القاعدة HTML <base>' },
      result: { en: `Deceptive <base href="${baseTagHref}"> points to external host`, ar: `وسم <base href="${baseTagHref}"> يشير لنطاق خارجي` },
      status: 'failed',
      severity: 'high',
      weight: 24,
      evidence: `Base href: ${baseTagHref}`,
      explanation: {
        en: 'A malicious <base> tag redirects all relative links and resource paths to an attacker-controlled domain.',
        ar: 'يعيد وسم <base> الخبيث توجيه كافة الروابط النسبية وملفات الموقع نحو خادم يسيطر عليه المهاجم.',
      },
      recommendedAction: {
        en: 'Do not interact with this page; base-tag hijacking is a classic phishing cloaking technique.',
        ar: 'لا تتفاعل مع هذه الصفحة؛ التلاعب بوسم القاعدة هو أسلوب تصيد كلاسيكي.',
      },
      source: 'SM Source Intelligence',
      timestamp: now,
      confidence: 98,
    });
  }

  if (!securityHeaders.csp) {
    findings.push({
      id: 'source-csp-missing',
      section: 'source_intelligence',
      test: { en: 'Content Security Policy (CSP) Header', ar: 'ترويسة سياسة أمان المحتوى (CSP)' },
      result: { en: 'Content-Security-Policy header is missing', ar: 'ترويسة Content-Security-Policy مفقودة' },
      status: 'warning',
      severity: 'informational',
      weight: 0,
      evidence: 'Missing CSP header in HTTP response',
      explanation: {
        en: 'Absence of a Content Security Policy allows browser execution of injected scripts if an XSS vulnerability occurs.',
        ar: 'غياب سياسة CSP يتيح للمتصفح تنفيذ أي سكربت محقون في حال وجود ثغرة XSS.',
      },
      recommendedAction: {
        en: 'Implement a strict CSP policy in production.',
        ar: 'تفعيل سياسة CSP صارمة في بيئة الإنتاج.',
      },
      source: 'SM Header Inspector',
      timestamp: now,
      confidence: 100,
    });
  }

  return { sourceIntel, formDetails, supplyChain, findings };
}
