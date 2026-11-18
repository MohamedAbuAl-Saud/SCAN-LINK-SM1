import dns from 'node:dns/promises';
import net from 'node:net';
import type { CheckFinding, DomainIntelData } from '../types.ts';
import { isPrivateOrReservedIp } from '../security/ssrfGuard.ts';
import { detectPaasHosting, extractRegistrableDomain } from './urlIntelligence.ts';

let ianaRdapBootstrapCache: { map: Map<string, string>; expiresAt: number } | null = null;

async function fetchJsonWithTimeout(
  url: string,
  timeoutMs = 6000,
  extraHeaders: Record<string, string> = {}
): Promise<any | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: {
        Accept: 'application/rdap+json, application/json',
        'User-Agent': 'Mozilla/5.0 (compatible; ScanLinkSM/2.0)',
        ...extraHeaders,
      },
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function resolveAuthoritativeRdapBase(tld: string): Promise<string | null> {
  if (!ianaRdapBootstrapCache || Date.now() > ianaRdapBootstrapCache.expiresAt) {
    const bootstrap = await fetchJsonWithTimeout('https://data.iana.org/rdap/dns.json', 5000);
    if (bootstrap && Array.isArray(bootstrap.services)) {
      const map = new Map<string, string>();
      for (const svc of bootstrap.services) {
        if (!Array.isArray(svc) || svc.length < 2) continue;
        const tlds: string[] = Array.isArray(svc[0]) ? svc[0] : [];
        const urls: string[] = Array.isArray(svc[1]) ? svc[1] : [];
        const httpsUrl = urls.find((u) => u.startsWith('https://')) || urls[0];
        if (!httpsUrl) continue;
        for (const t of tlds) {
          map.set(t.toLowerCase(), httpsUrl.replace(/\/$/, ''));
        }
      }
      ianaRdapBootstrapCache = { map, expiresAt: Date.now() + 24 * 60 * 60 * 1000 };
    }
  }
  return ianaRdapBootstrapCache?.map.get(tld.toLowerCase()) || null;
}

function extractVcardField(vcardArray: any, fieldName: string): string | undefined {
  if (!Array.isArray(vcardArray) || vcardArray.length < 2 || !Array.isArray(vcardArray[1])) return undefined;
  for (const item of vcardArray[1]) {
    if (Array.isArray(item) && item[0] === fieldName && item[3]) {
      return String(item[3]);
    }
  }
  return undefined;
}

async function queryCloudflareDoH(
  hostname: string,
  type: 'A' | 'AAAA' | 'DS' | 'DNSKEY'
): Promise<{ answers: { data: string; ttl: number }[]; adFlag: boolean }> {
  const json = await fetchJsonWithTimeout(
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=${type}&do=1`,
    4500,
    { Accept: 'application/dns-json' }
  );
  if (!json) return { answers: [], adFlag: false };
  const answers = Array.isArray(json.Answer)
    ? json.Answer.filter((ans: any) => typeof ans?.data === 'string').map((ans: any) => ({
        data: String(ans.data),
        ttl: Number(ans.TTL || 0),
      }))
    : [];
  return { answers, adFlag: Boolean(json.AD) };
}

async function queryWhoisPort43Fallback(
  domain: string
): Promise<{ registrar?: string; registrationDate?: string; expirationDate?: string; source?: string } | null> {
  const whoisQuery = (host: string, query: string): Promise<string> =>
    new Promise((resolve, reject) => {
      const chunks: Buffer[] = [];
      const socket = net.createConnection({ host, port: 43, timeout: 3500 }, () => {
        socket.write(`${query}\r\n`);
      });
      socket.on('data', (d) => chunks.push(d));
      socket.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      socket.on('timeout', () => {
        socket.destroy();
        reject(new Error('WHOIS timeout'));
      });
      socket.on('error', (err) => {
        socket.destroy();
        reject(err);
      });
    });

  try {
    const ianaRaw = await whoisQuery('whois.iana.org', domain);
    const referMatch = ianaRaw.match(/^refer:\s*(\S+)/im);
    const whoisHost = referMatch?.[1]?.trim();
    if (!whoisHost) return null;

    // SSRF guard check on whois host
    const ips = await dns.lookup(whoisHost, { all: true }).catch(() => []);
    if (!ips.length || ips.some((r) => isPrivateOrReservedIp(r.address))) return null;

    const raw = await whoisQuery(whoisHost, domain);
    const createdMatch = raw.match(/(?:Creation Date|Created On|Registered On|Registration Date|created):\s*([^\r\n]+)/i);
    const expiryMatch = raw.match(/(?:Registry Expiry Date|Expiration Date|Expiry Date|paid-till):\s*([^\r\n]+)/i);
    const registrarMatch = raw.match(/(?:Registrar|Sponsoring Registrar):\s*([^\r\n]+)/i);

    let registrationDate: string | undefined;
    if (createdMatch?.[1]) {
      const ts = Date.parse(createdMatch[1].trim());
      if (!Number.isNaN(ts)) registrationDate = new Date(ts).toISOString();
    }
    let expirationDate: string | undefined;
    if (expiryMatch?.[1]) {
      const ts = Date.parse(expiryMatch[1].trim());
      if (!Number.isNaN(ts)) expirationDate = new Date(ts).toISOString();
    }

    return {
      registrar: registrarMatch?.[1]?.trim(),
      registrationDate,
      expirationDate,
      source: whoisHost,
    };
  } catch {
    return null;
  }
}

function detectDnsProvider(ns: string[], soa?: string): string | undefined {
  const joined = `${ns.join(' ')} ${soa || ''}`.toLowerCase();
  if (joined.includes('cloudflare.com')) return 'Cloudflare DNS';
  if (joined.includes('awsdns')) return 'Amazon Route 53';
  if (joined.includes('azure-dns')) return 'Microsoft Azure DNS';
  if (joined.includes('domaincontrol.com')) return 'GoDaddy DNS';
  if (joined.includes('registrar-servers.com')) return 'Namecheap BasicDNS';
  if (joined.includes('digitalocean.com')) return 'DigitalOcean DNS';
  if (joined.includes('akam.net') || joined.includes('edgekey.net')) return 'Akamai Edge DNS';
  if (joined.includes('googledomains') || joined.includes('ns-cloud')) return 'Cloud DNS Provider';
  if (joined.includes('wikimedia.org')) return 'Wikimedia Authoritative DNS';
  if (joined.includes('verisign')) return 'Verisign Managed DNS';
  if (joined.includes('dnsmadeeasy')) return 'DNS Made Easy';
  if (joined.includes('nsone.net')) return 'IBM NS1 DNS';
  return undefined;
}

function detectCdnOrReverseProxy(
  ns: string[],
  cname: string[],
  networkName: string | undefined,
  httpHeaders: Record<string, string>
): string | undefined {
  const server = (httpHeaders['server'] || '').toLowerCase();
  const cnames = cname.join(' ').toLowerCase();
  const nss = ns.join(' ').toLowerCase();
  const netLower = (networkName || '').toLowerCase();

  if (httpHeaders['cf-ray'] || server.includes('cloudflare') || netLower.includes('cloudflare') || nss.includes('cloudflare.com')) {
    return 'Cloudflare (Reverse Proxy / CDN)';
  }
  if (httpHeaders['x-amz-cf-id'] || httpHeaders['x-amz-cf-pop'] || cnames.includes('cloudfront.net') || server.includes('cloudfront')) {
    return 'Amazon CloudFront CDN';
  }
  if (httpHeaders['x-vercel-id'] || server === 'vercel' || cnames.includes('vercel-dns.com')) {
    return 'Vercel Edge Network';
  }
  if (httpHeaders['x-nf-request-id'] || server === 'netlify' || cnames.includes('netlify')) {
    return 'Netlify Edge CDN';
  }
  if (server.includes('fastly') || httpHeaders['x-served-by']?.includes('cache-') || netLower.includes('fastly') || cnames.includes('fastly.net')) {
    return 'Fastly CDN';
  }
  if (server.includes('akamaighost') || cnames.includes('akamai') || netLower.includes('akamai')) {
    return 'Akamai CDN';
  }
  if (httpHeaders['x-azure-ref'] || cnames.includes('azurefd.net')) {
    return 'Azure Front Door';
  }
  if (server.includes('github.com') || cnames.includes('github.io')) {
    return 'GitHub Pages CDN';
  }
  return undefined;
}

export async function analyzeDomainAndDns(
  asciiHostname: string,
  httpHeaders: Record<string, string> = {}
): Promise<{ data: DomainIntelData; findings: CheckFinding[] }> {
  const now = new Date().toISOString();
  const findings: CheckFinding[] = [];
  const isIp = net.isIP(asciiHostname.replace(/^\[|\]$/g, '')) !== 0;
  const registrableDomain = isIp ? asciiHostname : extractRegistrableDomain(asciiHostname);
  const paas = detectPaasHosting(asciiHostname);

  // 1. Live DNS Queries (A, AAAA, MX, NS, TXT, CNAME, SOA, DoH A + DNSSEC)
  const [aRes, aaaaRes, mxRes, nsRes, txtRes, cnameRes, soaRes, dohARes, dohDsRes] = await Promise.allSettled([
    isIp ? Promise.resolve([asciiHostname]) : dns.resolve4(asciiHostname),
    isIp ? Promise.resolve([]) : dns.resolve6(asciiHostname),
    isIp ? Promise.resolve([]) : dns.resolveMx(registrableDomain),
    isIp ? Promise.resolve([]) : dns.resolveNs(registrableDomain),
    isIp ? Promise.resolve([]) : dns.resolveTxt(registrableDomain),
    isIp ? Promise.resolve([]) : dns.resolveCname(asciiHostname),
    isIp ? Promise.resolve(null) : dns.resolveSoa(registrableDomain),
    isIp ? Promise.resolve({ answers: [], adFlag: false }) : queryCloudflareDoH(asciiHostname, 'A'),
    isIp ? Promise.resolve({ answers: [], adFlag: false }) : queryCloudflareDoH(registrableDomain, 'DS'),
  ]);

  const a = aRes.status === 'fulfilled' ? aRes.value : [];
  const aaaa = aaaaRes.status === 'fulfilled' ? aaaaRes.value : [];
  const mx = mxRes.status === 'fulfilled' ? mxRes.value.map((m) => `${m.exchange} (p${m.priority})`) : [];
  const ns = nsRes.status === 'fulfilled' ? nsRes.value : [];
  const txt = txtRes.status === 'fulfilled' ? txtRes.value.map((chunks) => chunks.join('')) : [];
  const cname = cnameRes.status === 'fulfilled' ? cnameRes.value : [];
  const soaObj = soaRes.status === 'fulfilled' ? soaRes.value : null;
  const soa = soaObj ? `${soaObj.nsname} (${soaObj.hostmaster}, serial ${soaObj.serial}, ttl ${soaObj.minttl}s)` : undefined;

  const dohAData = dohARes.status === 'fulfilled' ? dohARes.value : { answers: [], adFlag: false };
  const dohDsData = dohDsRes.status === 'fulfilled' ? dohDsRes.value : { answers: [], adFlag: false };
  const dohVerified = dohAData.answers.length > 0;
  const dnssecValidated = isIp
    ? null
    : dohAData.adFlag || dohDsData.adFlag || dohDsData.answers.length > 0
      ? true
      : dohVerified
        ? false
        : null;

  const ttls = dohAData.answers.map((ans) => ans.ttl).filter((t) => Number.isFinite(t) && t > 0);
  const minTtlSeconds = ttls.length > 0 ? Math.min(...ttls) : undefined;
  const distinctSubnets = new Set(a.map((ip) => ip.split('.').slice(0, 3).join('.')));
  const fastFluxSuspected = Boolean(minTtlSeconds !== undefined && minTtlSeconds <= 60 && distinctSubnets.size >= 4);

  const primaryIp = a[0] || aaaa[0];
  let ptr: string[] = [];
  if (primaryIp) {
    try {
      ptr = await dns.reverse(primaryIp);
    } catch {
      ptr = [];
    }
  }

  const hasSpf = txt.some((t) => t.toLowerCase().includes('v=spf1'));
  let hasDmarc = false;
  if (!isIp) {
    try {
      const dmarcRecords = await dns.resolveTxt(`_dmarc.${registrableDomain}`);
      hasDmarc = dmarcRecords.some((chunks) => chunks.join('').toLowerCase().includes('v=dmarc1'));
    } catch {
      hasDmarc = false;
    }
  }

  const dnsProvider = detectDnsProvider(ns, soa);

  findings.push({
    id: 'dns-resolution',
    section: 'dns_analysis',
    test: { en: 'DNS, SOA, Reverse PTR, DNSSEC & TTL Resolution', ar: 'تحليل سجلات DNS و SOA و PTR و DNSSEC وزمن TTL' },
    result:
      a.length > 0 || aaaa.length > 0
        ? {
            en: `${a.length} A, ${aaaa.length} AAAA, ${ns.length} NS, ${mx.length} MX · DNSSEC: ${dnssecValidated === true ? 'Validated' : dnssecValidated === false ? 'Not Signed' : 'Unknown'}${minTtlSeconds ? ` · Min TTL ${minTtlSeconds}s` : ''}`,
            ar: `${a.length} سجل A، ${aaaa.length} AAAA، ${ns.length} NS · DNSSEC: ${dnssecValidated === true ? 'مفعل' : dnssecValidated === false ? 'غير موقع' : 'غير محدد'}${minTtlSeconds ? ` · أقل TTL ${minTtlSeconds}ث` : ''}`,
          }
        : { en: 'No public A/AAAA records resolved', ar: 'لم يتم العثور على سجلات عناوين عامة' },
    status: fastFluxSuspected ? 'warning' : a.length > 0 || aaaa.length > 0 ? 'pass' : 'failed',
    severity: fastFluxSuspected ? 'medium' : a.length > 0 || aaaa.length > 0 ? 'informational' : 'high',
    weight: fastFluxSuspected ? 10 : a.length > 0 || aaaa.length > 0 ? 0 : 18,
    evidence: `A: [${a.join(', ')}] | AAAA: [${aaaa.join(', ')}] | CNAME: [${cname.join(', ') || 'none'}] | NS: [${ns.join(', ')}] | SOA: ${soa ?? 'N/A'} | PTR: [${ptr.join(', ') || 'none'}] | DNSSEC: ${dnssecValidated} | MinTTL: ${minTtlSeconds ?? 'N/A'}s | FastFluxHeuristic: ${fastFluxSuspected}`,
    explanation: {
      en: fastFluxSuspected
        ? `Very short DNS TTL (${minTtlSeconds}s) paired with ${distinctSubnets.size} distinct /24 IP subnets suggests rapid IP rotation (Fast Flux indicator).`
        : a.length > 0 || aaaa.length > 0
          ? `Domain resolves to public IP addresses via OS DNS${dohVerified ? ' and Cloudflare DoH' : ''}${dnsProvider ? ` (${dnsProvider})` : ''}.`
          : 'Hostname failed to resolve to public IPv4/IPv6 addresses.',
      ar: fastFluxSuspected
        ? `قصر زمن TTL جداً (${minTtlSeconds} ثانية) مع تعدد الشبكات الفرعية (${distinctSubnets.size}) قد يشير إلى دوران سريع لعناوين IP (Fast Flux).`
        : a.length > 0 || aaaa.length > 0
          ? `يشير النطاق إلى عناوين IP عامة موثقة${dnsProvider ? ` عبر ${dnsProvider}` : ''}.`
          : 'فشل النطاق في إرجاع سجلات عناوين عامة.',
    },
    recommendedAction: {
      en: fastFluxSuspected
        ? 'Correlate short-TTL DNS rotation with domain age and threat feeds.'
        : a.length > 0 || aaaa.length > 0
          ? 'No action required.'
          : 'Verify domain spelling; non-resolving domains cannot be verified safe.',
      ar: fastFluxSuspected
        ? 'قارن دوران العناوين السريع بعمر النطاق وقوائم التهديدات.'
        : a.length > 0 || aaaa.length > 0
          ? 'لا يلزم إجراء.'
          : 'تحقق من صحة النطاق؛ تعذر حل العنوان يمنع إتمام الفحص.',
    },
    forensic: {
      whereDetected: {
        en: `DNS records for "${asciiHostname}" and root zone "${registrableDomain}"`,
        ar: `سجلات DNS للنطاق "${asciiHostname}" والمنطقة الجذرية "${registrableDomain}"`,
      },
      whyRisky: {
        en: 'Fast-flux networks rotate ephemeral IPs behind short TTLs to evade takedowns; missing DNSSEC leaves DNS answers unsigned.',
        ar: 'تُستخدم تقنية Fast Flux لتغيير الخوادم بسرعة والتهرب من الحظر، كما أن غياب DNSSEC يترك الردود غير موقعة رقمياً.',
      },
      howExploited: {
        en: 'Malicious infrastructures rapidly cycle compromised proxy bots using low-TTL A records.',
        ar: 'تدوّر البنى الخبيثة عناوين خوادم وسيطة مصابة خلال ثوانٍ عبر قيم TTL منخفضة للغاية.',
      },
      userImpact: {
        en: 'Users are routed to transient attacker servers that disappear quickly after credential capture.',
        ar: 'توجيه المستخدم نحو خوادم متغيرة تختفي سريعاً بعد سرقة البيانات.',
      },
      notProvenAlone: {
        en: 'Low TTL (30–300s) is routinely used by major CDNs (Cloudflare, AWS, Fastly) for load balancing and is NOT proof of Fast Flux or malice alone; absence of DNSSEC is common even on major legitimate sites.',
        ar: 'قيمة TTL المنخفضة وغياب DNSSEC شائعان جداً في مواقع موثوقة تستخدم شبكات CDN ولا يثبتان وحدهما أي نشاط خبيث.',
      },
    },
    source: dohVerified ? 'Node DNS + Cloudflare DoH' : 'Node DNS Resolver',
    timestamp: now,
    confidence: 95,
  });

  if (!isIp) {
    findings.push({
      id: 'dns-email-security',
      section: 'dns_analysis',
      test: { en: 'Email Authentication (SPF & DMARC)', ar: 'توثيق البريد الإلكتروني (SPF و DMARC)' },
      result: {
        en: `SPF: ${hasSpf ? 'Present' : 'Missing'} · DMARC: ${hasDmarc ? 'Present' : 'Missing'}`,
        ar: `SPF: ${hasSpf ? 'متوفر' : 'غير موجود'} · DMARC: ${hasDmarc ? 'متوفر' : 'غير موجود'}`,
      },
      status: hasSpf && hasDmarc ? 'pass' : 'warning',
      severity: 'informational',
      weight: 0,
      evidence: `SPF: ${hasSpf} | DMARC: ${hasDmarc}`,
      explanation: {
        en:
          hasSpf && hasDmarc
            ? 'Domain publishes both SPF and DMARC authentication policies.'
            : 'Missing SPF/DMARC records are common on disposable domains, though many web-only legitimate domains omit them.',
        ar:
          hasSpf && hasDmarc
            ? 'ينشر النطاق سياسات SPF و DMARC لحماية البريد الإلكتروني.'
            : 'غياب سجلات SPF أو DMARC شائع في النطاقات المؤقتة وإن وجد أحياناً في مواقع ويب لا ترسل بريداً.',
      },
      recommendedAction: {
        en: 'Review alongside domain age and page content.',
        ar: 'راجع هذه النتيجة مع عمر النطاق ومحتوى الصفحة.',
      },
      forensic: {
        whereDetected: {
          en: `TXT records for "${registrableDomain}" and "_dmarc.${registrableDomain}"`,
          ar: `سجلات TXT للنطاق "${registrableDomain}" و "_dmarc.${registrableDomain}"`,
        },
        whyRisky: {
          en: 'Domains without SPF/DMARC lack sender spoofing protection and frequently appear on throwaway attacker infrastructure.',
          ar: 'النطاقات بدون SPF/DMARC تفتقر لحماية انتحال البريد وتكثر في البنى المؤقتة للمهاجمين.',
        },
        howExploited: {
          en: 'Throwaway phishing domains skip email security setup because they only serve short-lived web lures.',
          ar: 'يهمل المهاجم إعداد سياسات البريد على النطاقات المؤقتة المصممة لحملات ويب قصيرة الأجل.',
        },
        userImpact: {
          en: 'Higher likelihood of spoofed emails or unverified domain administration.',
          ar: 'زيادة احتمال ضعف الموثوقية الإدارية للنطاق.',
        },
        notProvenAlone: {
          en: 'Absence of SPF/DMARC NEVER proves a website is malicious; web-only or parked domains often omit mail records.',
          ar: 'غياب SPF/DMARC لا يثبت أبداً أن الموقع خبيث؛ فكثير من المواقع غير البريدية لا تنشر هذه السجلات.',
        },
      },
      source: 'DNS TXT Lookup',
      timestamp: now,
      confidence: 90,
    });
  }

  // 2. RDAP + Port-43 WHOIS Fallback Domain Registration Intelligence
  let registrationDate: string | undefined;
  let expirationDate: string | undefined;
  let lastUpdatedDate: string | undefined;
  let domainAgeDays: number | undefined;
  let domainAgeYears: number | undefined;
  let registrar: string | undefined;
  let registry: string | undefined;
  let statuses: string[] = [];
  let rdapNameservers: string[] = [];
  let privacyProtected: boolean | null = null;
  let rdapUsedUrl: string | undefined;
  let whoisSource: string | undefined;
  let ownerSummary: { en: string; ar: string } = {
    en: 'Unavailable from public RDAP/WHOIS',
    ar: 'غير متوفر عبر سجلات RDAP/WHOIS العامة',
  };

  if (!isIp) {
    const tld = registrableDomain.split('.').pop() || '';
    const authBase = await resolveAuthoritativeRdapBase(tld);
    const rdapEndpoint = authBase
      ? `${authBase}/domain/${encodeURIComponent(registrableDomain)}`
      : `https://rdap.org/domain/${encodeURIComponent(registrableDomain)}`;
    rdapUsedUrl = rdapEndpoint;
    if (authBase) {
      try {
        registry = new URL(authBase).hostname;
      } catch {
        // ignore
      }
    }

    const rdap = await fetchJsonWithTimeout(rdapEndpoint, 6500);
    if (rdap) {
      if (Array.isArray(rdap.events)) {
        for (const ev of rdap.events) {
          if (ev.eventAction === 'registration' && ev.eventDate) registrationDate = ev.eventDate;
          if (ev.eventAction === 'expiration' && ev.eventDate) expirationDate = ev.eventDate;
          if (
            (ev.eventAction === 'last changed' || ev.eventAction === 'last update of RDAP database') &&
            ev.eventDate
          ) {
            lastUpdatedDate = ev.eventDate;
          }
        }
      }
      if (Array.isArray(rdap.status)) {
        statuses = rdap.status.map(String);
      }
      if (Array.isArray(rdap.nameservers)) {
        rdapNameservers = rdap.nameservers
          .map((n: any) => n?.ldhName || n?.unicodeName)
          .filter(Boolean)
          .map(String);
      }
      if (Array.isArray(rdap.entities)) {
        for (const ent of rdap.entities) {
          const roles: string[] = Array.isArray(ent.roles) ? ent.roles : [];
          if (roles.includes('registrar')) {
            registrar = extractVcardField(ent.vcardArray, 'fn') || ent.handle;
          }
          if (roles.includes('registrant')) {
            const registrantFn = extractVcardField(ent.vcardArray, 'fn');
            const registrantOrg = extractVcardField(ent.vcardArray, 'org');
            const remarksText = JSON.stringify(ent.remarks || []).toLowerCase();
            const isRedacted =
              remarksText.includes('redact') ||
              remarksText.includes('privacy') ||
              (registrantFn && /privacy|redacted|proxy|whoisguard|withheld/i.test(registrantFn));

            if (isRedacted || (!registrantFn && !registrantOrg)) {
              privacyProtected = true;
              ownerSummary = {
                en: 'Protected / Redacted by WHOIS Privacy Policy (Normal under GDPR)',
                ar: 'محمي ومخفي بموجب سياسة خصوصية WHOIS/RDAP (إجراء قياسي شائع)',
              };
            } else {
              privacyProtected = false;
              ownerSummary = {
                en: [registrantFn, registrantOrg].filter(Boolean).join(' · '),
                ar: [registrantFn, registrantOrg].filter(Boolean).join(' · '),
              };
            }
          }
        }
      }

      if (privacyProtected === null) {
        const topRemarks = JSON.stringify(rdap.remarks || []).toLowerCase();
        if (topRemarks.includes('redact') || topRemarks.includes('privacy') || topRemarks.includes('gdpr')) {
          privacyProtected = true;
          ownerSummary = {
            en: 'Redacted for Privacy (GDPR / Registry Policy — Unavailable)',
            ar: 'مخفي للخصوصية وفق سياسة المسجل (غير متاح)',
          };
        } else {
          privacyProtected = true;
          ownerSummary = {
            en: 'Registrant details withheld by registry RDAP policy (Unavailable)',
            ar: 'تفاصيل المالك محجوبة بموجب سياسة سجل RDAP (غير متاحة)',
          };
        }
      }
    }

    // Port 43 WHOIS fallback when RDAP lacked creation timestamp or registrar
    if (!registrationDate || !registrar) {
      const whois = await queryWhoisPort43Fallback(registrableDomain);
      if (whois) {
        whoisSource = whois.source;
        if (!registrationDate && whois.registrationDate) registrationDate = whois.registrationDate;
        if (!expirationDate && whois.expirationDate) expirationDate = whois.expirationDate;
        if (!registrar && whois.registrar) registrar = whois.registrar;
      }
    }

    if (registrationDate) {
      const regTime = Date.parse(registrationDate);
      if (!Number.isNaN(regTime)) {
        domainAgeDays = Math.max(0, Math.floor((Date.now() - regTime) / (1000 * 60 * 60 * 24)));
        domainAgeYears = Number((domainAgeDays / 365.25).toFixed(1));
      }
    }

    if (domainAgeDays !== undefined) {
      const isVeryNew = domainAgeDays < 30;
      const isYoung = domainAgeDays < 180;
      findings.push({
        id: 'domain-age',
        section: 'domain_intelligence',
        test: { en: 'Domain Registration Age (RDAP / WHOIS)', ar: 'عمر تسجيل النطاق (RDAP / WHOIS)' },
        result: paas.isPaas
          ? {
              en: `Parent PaaS domain ${domainAgeDays}d (${domainAgeYears}y) — does not reflect hosted page age`,
              ar: `عمر النطاق الأم ${domainAgeDays} يوماً (${domainAgeYears} سنة) — لا يعكس عمر الصفحة المنشورة`,
            }
          : {
              en: `${domainAgeDays} day(s) / ${domainAgeYears} year(s) old (registered ${registrationDate?.slice(0, 10)})`,
              ar: `العمر ${domainAgeDays} يوماً (${domainAgeYears} سنة · مسجل في ${registrationDate?.slice(0, 10)})`,
            },
        status: paas.isPaas ? 'warning' : isVeryNew ? 'failed' : isYoung ? 'warning' : 'pass',
        severity: paas.isPaas ? 'low' : isVeryNew ? 'high' : isYoung ? 'medium' : 'informational',
        weight: paas.isPaas ? 0 : isVeryNew ? 24 : isYoung ? 10 : 0,
        evidence: `Registered: ${registrationDate} | AgeDays: ${domainAgeDays} | AgeYears: ${domainAgeYears} | Updated: ${lastUpdatedDate ?? 'N/A'} | Expires: ${expirationDate ?? 'N/A'} | Registrar: ${registrar ?? 'Unknown'} | Registry: ${registry ?? whoisSource ?? 'RDAP'} | PrivacyProtected: ${privacyProtected} | Multi-tenant PaaS: ${paas.isPaas}`,
        explanation: {
          en: paas.isPaas
            ? `Domain age reflects ${paas.provider} infrastructure, not the individual page or subdomain creator. Old platform domains cannot be treated as safe.`
            : isVeryNew
              ? 'Domain was registered within the last 30 days. Newly registered domains are strongly associated with short-lived phishing campaigns.'
              : isYoung
                ? 'Domain is under 6 months old; evaluate content and impersonation signals carefully.'
                : 'Domain has an established registration history. Note: older or compromised domains can still host phishing or malware.',
          ar: paas.isPaas
            ? `يعكس عمر النطاق البنية التحتية لـ ${paas.provider} وليس تاريخ إنشاء الصفحة الفرعية.`
            : isVeryNew
              ? 'تم تسجيل النطاق خلال آخر 30 يوماً، وهو مؤشر خطورة يرتبط غالباً بحملات التصيد الحديثة.'
              : isYoung
                ? 'عمر النطاق أقل من 6 أشهر؛ قيّم المحتوى وانتحال العلامات بعناية.'
                : 'يمتلك النطاق سجلاً زمنياً مستقراً؛ علماً بأن النطاقات القديمة قد تُخترق وتستضيف صفحات ضارة.',
        },
        recommendedAction: {
          en: isVeryNew ? 'Avoid entering credentials on newly registered domains.' : 'Evaluate alongside page content, identity deception, and threat feeds.',
          ar: isVeryNew ? 'تجنب إدخال بيانات حساسة في نطاقات مسجلة حديثاً.' : 'قيّم النتيجة مع فحص المحتوى وخداع النطاق وقواعد التهديدات.',
        },
        forensic: {
          whereDetected: {
            en: `Authoritative registration record for "${registrableDomain}"`,
            ar: `سجل التسجيل الرسمي للنطاق "${registrableDomain}"`,
          },
          whyRisky: {
            en: 'Throwaway phishing domains are typically registered hours or days before an attack campaign.',
            ar: 'يتم تسجيل نطاقات التصيد المؤقتة قبل ساعات أو أيام قليلة فقط من إطلاق الحملة الاحتيالية.',
          },
          howExploited: {
            en: 'Attackers bulk-register cheap domains or abuse aged PaaS subdomains so reputational blocklists take time to catch up.',
            ar: 'يسجل المهاجم نطاقات رخيصة حديثة أو يستغل نطاقات استضافة قديمة قبل إدراجها في قوائم الحظر.',
          },
          userImpact: {
            en: 'Zero historical accountability if credentials or funds are stolen.',
            ar: 'غياب أي سجل موثوق للنطاق عند التعرض للسرقة أو الاحتيال.',
          },
          notProvenAlone: {
            en: 'WHOIS privacy protection is NOT suspicious (required under GDPR), and domain age alone neither proves malice (legitimate startups) nor guarantees safety (compromised old domains).',
            ar: 'إخفاء بيانات المالك في WHOIS ليس دليلاً على الاحتيال، كما أن قِدم النطاق لا يثبت أمانه في حال اختراقه.',
          },
        },
        source: registry ? `Authoritative RDAP (${registry})` : whoisSource ? `WHOIS (${whoisSource})` : 'RDAP Registry',
        timestamp: now,
        confidence: 95,
      });
    } else {
      findings.push({
        id: 'domain-age',
        section: 'domain_intelligence',
        test: { en: 'Domain Registration Age (RDAP / WHOIS)', ar: 'عمر تسجيل النطاق (RDAP / WHOIS)' },
        result: { en: 'RDAP/WHOIS registration metadata unavailable', ar: 'بيانات التسجيل غير متاحة من RDAP أو WHOIS' },
        status: 'unknown',
        severity: 'unknown',
        weight: 0,
        evidence: `RDAP (${rdapUsedUrl}) and WHOIS fallback returned no creation date`,
        explanation: {
          en: 'Public RDAP/WHOIS did not return a creation timestamp for this TLD. Missing registration metadata is never treated as proof of safety.',
          ar: 'لم يُرجع سجل RDAP/WHOIS العام تاريخ إنشاء النطاق. غياب البيانات لا يُحسب كدليل أمان.',
        },
        recommendedAction: {
          en: 'Treat domain ownership and age as unverified.',
          ar: 'اعتبر ملكية النطاق وعمره غير متحقق منهما.',
        },
        source: 'RDAP / WHOIS',
        timestamp: now,
        confidence: 25,
      });
    }
  }

  // 3. Deep IP Intelligence (ARIN RDAP + ipwho.is Geolocation/ASN + Shodan InternetDB Ports/CVEs/Tags)
  let asn: string | undefined;
  let networkName: string | undefined;
  let country: string | undefined;
  let cdnOrProxyProvider: string | undefined;
  let ipIntel: DomainIntelData['ipIntel'] | undefined;

  if (primaryIp) {
    const [ipRdap, ipWho, shodanDb] = await Promise.all([
      fetchJsonWithTimeout(`https://rdap.arin.net/registry/ip/${encodeURIComponent(primaryIp)}`, 4500),
      fetchJsonWithTimeout(`https://ipwho.is/${encodeURIComponent(primaryIp)}`, 4500),
      fetchJsonWithTimeout(`https://internetdb.shodan.io/${encodeURIComponent(primaryIp)}`, 4500),
    ]);

    let city: string | undefined;
    let region: string | undefined;
    let countryCode: string | undefined;
    let isp: string | undefined;
    let org: string | undefined;

    if (ipWho && ipWho.success !== false) {
      isp = ipWho.connection?.isp;
      org = ipWho.connection?.org;
      networkName = isp || org || ipRdap?.name;
      country = ipWho.country || ipWho.country_code;
      countryCode = ipWho.country_code;
      city = ipWho.city;
      region = ipWho.region;
      if (ipWho.connection?.asn) {
        asn = `AS${ipWho.connection.asn}`;
      }
    } else if (ipRdap) {
      networkName = ipRdap.name || ipRdap.handle;
      country = ipRdap.country;
      countryCode = ipRdap.country;
      if (Array.isArray(ipRdap.arin_originas0_originautnums) && ipRdap.arin_originas0_originautnums.length > 0) {
        asn = `AS${ipRdap.arin_originas0_originautnums[0]}`;
      } else if (ipRdap.handle) {
        asn = ipRdap.handle;
      }
    }

    const openPorts: number[] = Array.isArray(shodanDb?.ports) ? shodanDb.ports.map(Number) : [];
    const vulns: string[] = Array.isArray(shodanDb?.vulns) ? shodanDb.vulns.map(String) : [];
    const cpes: string[] = Array.isArray(shodanDb?.cpes) ? shodanDb.cpes.map(String) : [];
    const tags: string[] = Array.isArray(shodanDb?.tags) ? shodanDb.tags.map(String) : [];
    const shodanHosts: string[] = Array.isArray(shodanDb?.hostnames) ? shodanDb.hostnames.map(String) : [];

    cdnOrProxyProvider = detectCdnOrReverseProxy(ns, cname, networkName, httpHeaders);

    ipIntel = {
      ip: primaryIp,
      city,
      region,
      country,
      countryCode,
      isp,
      org,
      asn,
      reversePtr: ptr,
      isHostingOrProxy: Boolean(cdnOrProxyProvider || tags.some((t) => /cloud|vpn|proxy|tor/i.test(t))),
      openPorts,
      vulns,
      cpes,
      tags,
      hostnames: shodanHosts,
      source: shodanDb ? 'ARIN RDAP + ipwho.is + Shodan InternetDB' : 'ARIN RDAP + ipwho.is',
    };

    const riskyTags = tags.filter((t) => /compromised|malware|botnet|doublepulsar|c2|ransom/i.test(t));
    const sensitiveOpenPorts = cdnOrProxyProvider
      ? []
      : openPorts.filter((p) => [21, 22, 23, 445, 3389, 5900, 6379, 27017].includes(p));
    const nonCdnVulns = cdnOrProxyProvider ? [] : vulns;

    findings.push({
      id: 'domain-ip-hosting',
      section: 'domain_intelligence',
      test: { en: 'Deep IP, ASN, Open Ports, CVEs & Reverse Proxy Intel', ar: 'الفحص العميق لعنوان IP و ASN والمنافذ والثغرات و CDN' },
      result: {
        en: `${primaryIp}${asn ? ` · ${asn}` : ''}${networkName ? ` · ${networkName}` : ''}${city || country ? ` (${[city, countryCode || country].filter(Boolean).join(', ')})` : ''}${openPorts.length > 0 ? ` · ${openPorts.length} port(s)` : ''}${nonCdnVulns.length > 0 ? ` · ${nonCdnVulns.length} CVE(s)` : ''}`,
        ar: `${primaryIp}${asn ? ` · ${asn}` : ''}${networkName ? ` · ${networkName}` : ''}${city || country ? ` (${[city, countryCode || country].filter(Boolean).join('، ')})` : ''}${openPorts.length > 0 ? ` · ${openPorts.length} منفذ` : ''}${nonCdnVulns.length > 0 ? ` · ${nonCdnVulns.length} ثغرة CVE` : ''}`,
      },
      status: riskyTags.length > 0 ? 'failed' : sensitiveOpenPorts.length > 0 ? 'warning' : networkName || country ? 'pass' : 'unknown',
      severity: riskyTags.length > 0 ? 'high' : sensitiveOpenPorts.length > 0 ? 'medium' : 'informational',
      weight: riskyTags.length > 0 ? 25 : 0,
      evidence: `IP: ${primaryIp} | ASN: ${asn ?? 'N/A'} | ISP/Org: ${networkName ?? 'Unknown'} | Location: ${[city, region, country].filter(Boolean).join(', ') || 'Unknown'} | CDN/Proxy: ${cdnOrProxyProvider ?? 'None'} | OpenPorts: [${openPorts.join(', ') || 'none'}] | CVEs: [${vulns.slice(0, 8).join(', ') || 'none'}] | Tags: [${tags.join(', ') || 'none'}]`,
      explanation: {
        en: riskyTags.length > 0
          ? `Shodan InternetDB flags IP ${primaryIp} with high-risk tags (${riskyTags.join(', ')}).`
          : cdnOrProxyProvider
            ? `Traffic terminates at ${cdnOrProxyProvider}. Reverse proxies mask origin servers; never infer site safety from CDN infrastructure.`
            : `Deep IP telemetry inspected via ARIN RDAP, ipwho.is, and Shodan InternetDB (${openPorts.length} exposed port(s), ${vulns.length} indexed CVE(s)).`,
        ar: riskyTags.length > 0
          ? `رصدت قاعدة بيانات Shodan InternetDB وسوم خطورة عالية على عنوان IP ${primaryIp} (${riskyTags.join('، ')}).`
          : cdnOrProxyProvider
            ? `يمر الاتصال عبر ${cdnOrProxyProvider} الذي يخفي عنوان الخادم الحقيقي ولا يعكس موثوقية مالك الموقع.`
            : `تم الفحص العميق لعنوان IP عبر ARIN RDAP وipwho.is وShodan InternetDB (${openPorts.length} منفذ مكشوف، ${vulns.length} ثغرة مسجلة).`,
      },
      recommendedAction: {
        en: riskyTags.length > 0
          ? 'Treat this IP infrastructure as high-risk and correlate with external threat feeds.'
          : 'Do not infer site owner identity or safety from CDN or cloud hosting metadata.',
        ar: riskyTags.length > 0
          ? 'تعامل مع بنية هذا الخادم بحذر شديد وقارنها مع مزودي التهديدات.'
          : 'لا تستنتج أمان الموقع من مزود الاستضافة أو شبكة CDN.',
      },
      forensic: {
        whereDetected: {
          en: `Resolved endpoint IP ${primaryIp}, HTTP headers, and Shodan InternetDB telemetry`,
          ar: `عنوان IP الوجهة ${primaryIp} وبيانات Shodan InternetDB`,
        },
        whyRisky: {
          en: 'Compromised hosts or exposed administration ports (SSH/RDP/SMB) increase the chance of malicious takeover.',
          ar: 'الخوادم المخترقة أو التي تكشف منافذ إدارة حساسة ترفع احتمالية استضافة محتوى ضار.',
        },
        howExploited: {
          en: 'Attackers compromise unpatched VPS servers to deploy phishing kits or botnet payloads.',
          ar: 'يستغل المهاجمون الخوادم غير المحدثة لزرع صفحات تصيد أو برمجيات خبيثة.',
        },
        userImpact: {
          en: 'Connecting to compromised or unpatched infrastructure risks deceptive content.',
          ar: 'الاتصال بخادم مخترق قد يعرض المستخدم لمحتوى احتيالي أو خبيث.',
        },
        notProvenAlone: {
          en: 'Open ports 80/443 and CDN nodes (Cloudflare, Fastly, AWS) are normal for legitimate websites; Shodan CVE indices on shared CDNs reflect edge proxies rather than the website owner.',
          ar: 'المنافذ القياسية 80/443 وشبكات CDN طبيعية في المواقع الموثوقة، كما أن ثغرات الخادم المشترك لا تعني بالضرورة أن الموقع خبيث.',
        },
      },
      source: shodanDb ? 'ARIN RDAP · ipwho.is · Shodan InternetDB' : 'ARIN RDAP & IP Intelligence',
      timestamp: now,
      confidence: networkName ? 92 : 60,
    });
  }

  return {
    data: {
      domain: asciiHostname,
      registrableDomain,
      isMultiTenantPaas: paas.isPaas,
      paasProvider: paas.provider,
      registrationDate,
      expirationDate,
      lastUpdatedDate,
      domainAgeDays,
      domainAgeYears,
      registrar,
      registry,
      nameservers: ns.length > 0 ? ns : rdapNameservers,
      statuses,
      privacyProtected,
      ownerSummary,
      dnsRecords: {
        a,
        aaaa,
        mx,
        ns,
        txt,
        cname,
        soa,
        ptr,
        dnssecValidated,
        dnsProvider,
        cdnOrProxyProvider,
        minTtlSeconds,
        fastFluxSuspected,
        hasSpf,
        hasDmarc,
        dohVerified,
      },
      ipAddress: primaryIp,
      asn,
      networkName,
      country,
      rdapSource: rdapUsedUrl,
      whoisSource,
      ipIntel,
    },
    findings,
  };
}
