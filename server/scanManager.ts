import crypto from 'node:crypto';
import type { EventEmitter } from 'node:events';
import { EventEmitter as NodeEventEmitter } from 'node:events';
import { validateTargetAgainstSsrf } from './security/ssrfGuard.ts';
import { analyzeUrlIntelligence } from './analyzers/urlIntelligence.ts';
import { analyzeDomainDeceptionAndIdentity } from './analyzers/domainDeception.ts';
import { traceRedirectsSafely } from './analyzers/redirectAnalyzer.ts';
import { analyzeDomainAndDns } from './analyzers/domainIntelligence.ts';
import { inspectTlsCertificate } from './analyzers/tlsInspector.ts';
import { analyzeWebsiteContentAndBrand } from './analyzers/contentAnalyzer.ts';
import { analyzeSourceIntelligence } from './analyzers/sourceIntelligence.ts';
import { discoverAndInspectPages } from './analyzers/pageDiscovery.ts';
import { analyzeFileAndDownloads } from './analyzers/fileAnalyzer.ts';
import { recordProviderSuccess, runExternalThreatIntel } from './providers/threatIntelManager.ts';
import { captureWebsiteScreenshot, type ScreenshotViewportMode } from './analyzers/screenshotEngine.ts';
import { fetchSiteFaviconSafely } from './analyzers/faviconFetcher.ts';
import { computeRiskAndSections } from './analyzers/scoringEngine.ts';
import { assessDomainAuthenticity } from './analyzers/officialDomainRegistry.ts';
import type { CheckFinding, ScanJobState, ScanReport, ScanStageId, ScanStageProgress } from './types.ts';

const jobs = new Map<string, ScanJobState>();
const jobEmitters = new Map<string, EventEmitter>();

function createInitialStages(): ScanStageProgress[] {
  return [
    { id: 'url_validation', label: { en: 'URL validation, normalization & SSRF guard', ar: 'التحقق من الرابط والتطبيع وحماية SSRF' }, status: 'pending' },
    { id: 'dns_resolution', label: { en: 'URL structure & initial resolution', ar: 'تحليل بنية الرابط والتحضير الشبكي' }, status: 'pending' },
    { id: 'redirect_tracer', label: { en: 'Redirect chain tracing', ar: 'تتبع سلاسل إعادة التوجيه' }, status: 'pending' },
    { id: 'domain_rdap', label: { en: 'Domain deception, DNSSEC, RDAP & WHOIS lookup', ar: 'فحص خداع النطاق و DNSSEC و RDAP و WHOIS' }, status: 'pending' },
    { id: 'tls_inspection', label: { en: 'SSL/TLS certificate & cipher inspection', ar: 'فحص شهادة التشفير SSL/TLS والتشفير' }, status: 'pending' },
    { id: 'content_phishing', label: { en: 'Content, phishing, JS & file inspection', ar: 'فحص المحتوى والتصيد والملفات' }, status: 'pending' },
    { id: 'source_intelligence', label: { en: 'Website Source Intelligence & Supply Chain', ar: 'استخبارات مصدر الموقع وسلسلة التوريد' }, status: 'pending' },
    { id: 'page_discovery', label: { en: 'Multi-Page Website Discovery & Inspection', ar: 'استكشاف وفحص صفحات الموقع المتعددة' }, status: 'pending' },
    { id: 'threat_intel', label: { en: 'External threat intelligence checks', ar: 'استخبارات التهديدات الخارجية' }, status: 'pending' },
    { id: 'screenshot_capture', label: { en: 'Website screenshot capture', ar: 'التقاط المعاينة البصرية للموقع' }, status: 'pending' },
    { id: 'risk_scoring', label: { en: 'Deterministic risk calculation', ar: 'احتساب المخاطر والارتباط الأمني' }, status: 'pending' },
    { id: 'report_generation', label: { en: 'Security report generation', ar: 'توليد التقرير الأمني النهائي' }, status: 'pending' },
  ];
}

function updateStage(
  job: ScanJobState,
  stageId: ScanStageId,
  status: ScanStageProgress['status'],
  detail?: { en: string; ar: string },
  durationMs?: number
) {
  const stage = job.stages.find((s) => s.id === stageId);
  if (stage) {
    stage.status = status;
    if (detail) stage.detail = detail;
    if (durationMs !== undefined) stage.durationMs = durationMs;
  }
  const doneCount = job.stages.filter((s) => s.status !== 'pending' && s.status !== 'running').length;
  job.progressPercent = Math.round((doneCount / job.stages.length) * 100);
  jobEmitters.get(job.scanId)?.emit('update', job);
}

export function getScanJob(scanId: string): ScanJobState | undefined {
  return jobs.get(scanId);
}

export function getJobEmitter(scanId: string): EventEmitter | undefined {
  return jobEmitters.get(scanId);
}

export interface StartScanOptions {
  url: string;
  viewport?: ScreenshotViewportMode;
  disabledProviders?: string[];
}

export function startScanJob(options: StartScanOptions): ScanJobState {
  if (jobs.size >= 100) {
    const oldestKey = jobs.keys().next().value;
    if (oldestKey) {
      jobs.delete(oldestKey);
      jobEmitters.delete(oldestKey);
    }
  }

  const scanId = crypto.randomUUID();
  const job: ScanJobState = {
    scanId,
    submittedUrl: options.url,
    status: 'queued',
    progressPercent: 0,
    startedAt: new Date().toISOString(),
    stages: createInitialStages(),
  };

  jobs.set(scanId, job);
  jobEmitters.set(scanId, new NodeEventEmitter());

  void executeScanPipeline(job, options);
  return job;
}

async function executeScanPipeline(job: ScanJobState, options: StartScanOptions): Promise<void> {
  const pipelineStart = Date.now();
  job.status = 'running';
  const findings: CheckFinding[] = [];
  const viewportMode: ScreenshotViewportMode = options.viewport || 'desktop';

  try {
    // Stage 1: URL Validation, Normalization & SSRF Guard
    let t0 = Date.now();
    updateStage(job, 'url_validation', 'running');
    const validated = await validateTargetAgainstSsrf(options.url);
    updateStage(
      job,
      'url_validation',
      'completed',
      {
        en: `Normalized & resolved ${validated.asciiHostname} (${validated.pinnedIp})`,
        ar: `تم تطبيع وفحص ${validated.asciiHostname} (${validated.pinnedIp})`,
      },
      Date.now() - t0
    );

    // Stage 2: URL Structure Analysis
    t0 = Date.now();
    updateStage(job, 'dns_resolution', 'running');
    const urlIntel = analyzeUrlIntelligence(options.url, validated.normalizedUrl);
    findings.push(...urlIntel.findings);
    updateStage(
      job,
      'dns_resolution',
      urlIntel.findings.some((f) => f.status === 'failed') ? 'warning' : 'completed',
      {
        en: `${urlIntel.findings.length} structural indicator checks completed`,
        ar: `اكتمل فحص ${urlIntel.findings.length} مؤشراً لبنية الرابط`,
      },
      Date.now() - t0
    );

    // Stage 3: Redirect Chain Tracing
    t0 = Date.now();
    updateStage(job, 'redirect_tracer', 'running');
    const redirectRes = await traceRedirectsSafely(validated.normalizedUrl);
    findings.push(...redirectRes.findings);
    updateStage(
      job,
      'redirect_tracer',
      redirectRes.ssrfBlocked ? 'failed' : 'completed',
      {
        en: `${Math.max(0, redirectRes.hops.length - 1)} redirect hop(s) traced`,
        ar: `تم تتبع ${Math.max(0, redirectRes.hops.length - 1)} قفزة إعادة توجيه`,
      },
      Date.now() - t0
    );

    const finalParsed = new URL(redirectRes.finalUrl);
    const finalHost = finalParsed.hostname.toLowerCase();
    let finalPinnedIp = validated.pinnedIp;
    try {
      const revalidated = await validateTargetAgainstSsrf(redirectRes.finalUrl);
      finalPinnedIp = revalidated.pinnedIp;
    } catch {
      // Keep initial pinned IP
    }

    // Domain Deception & Identity Analysis
    const deceptionRes = analyzeDomainDeceptionAndIdentity({
      submittedUrl: options.url,
      finalUrl: redirectRes.finalUrl,
      redirects: redirectRes.hops,
      htmlBuffer: redirectRes.finalFetch?.buffer,
      contentType: redirectRes.finalFetch?.headers?.['content-type'],
    });
    findings.push(...deceptionRes.findings);

    // Stage 6: Content, Phishing, Brand Impersonation, JS & File Analysis
    t0 = Date.now();
    updateStage(job, 'content_phishing', 'running');
    const contentRes = analyzeWebsiteContentAndBrand(
      redirectRes.finalUrl,
      redirectRes.finalFetch?.status,
      redirectRes.finalFetch?.headers ?? {},
      redirectRes.finalFetch?.buffer,
      urlIntel.suspiciousPathTokens
    );
    findings.push(...contentRes.findings);

    const fileRes = analyzeFileAndDownloads(
      redirectRes.finalUrl,
      redirectRes.finalFetch?.headers ?? {},
      redirectRes.finalFetch?.buffer
    );
    findings.push(...fileRes.findings);

    updateStage(
      job,
      'content_phishing',
      contentRes.findings.some((f) => f.status === 'failed') ? 'warning' : 'completed',
      {
        en: contentRes.data
          ? `${contentRes.data.passwordInputCount} pwd field(s), ${contentRes.data.inlineScriptCount + contentRes.data.externalScriptCount} script(s)`
          : 'Content analyzed',
        ar: 'اكتمل فحص المحتوى والتصيد',
      },
      Date.now() - t0
    );

    // Stage 7: Website Source Intelligence & Supply Chain Analysis
    t0 = Date.now();
    updateStage(job, 'source_intelligence', 'running');
    const sourceRes = analyzeSourceIntelligence(
      redirectRes.finalUrl,
      redirectRes.finalFetch?.headers ?? {},
      redirectRes.finalFetch?.buffer
    );
    findings.push(...sourceRes.findings);
    updateStage(
      job,
      'source_intelligence',
      'completed',
      {
        en: `Analyzed ${sourceRes.supplyChain.totalExternalDomains} external domain(s), ${sourceRes.formDetails.length} form(s)`,
        ar: `تم تحليل ${sourceRes.supplyChain.totalExternalDomains} نطاقاً و${sourceRes.formDetails.length} نموذجاً`,
      },
      Date.now() - t0
    );

    // Stage 8: Multi-Page Discovery & Inspection
    t0 = Date.now();
    updateStage(job, 'page_discovery', 'running');
    const discoveryRes = await discoverAndInspectPages(redirectRes.finalUrl, redirectRes.finalFetch?.buffer);
    findings.push(...discoveryRes.findings);
    updateStage(
      job,
      'page_discovery',
      'completed',
      {
        en: `Discovered and inspected ${discoveryRes.pageDiscovery.inspectedCount} public sub-page(s)`,
        ar: `تم اكتشاف وفحص ${discoveryRes.pageDiscovery.inspectedCount} صفحة فرعية`,
      },
      Date.now() - t0
    );

    // Parallel background telemetry fetches (DNS, TLS, Threat Intel, Screenshot, Favicon)
    updateStage(job, 'domain_rdap', 'running');
    updateStage(job, 'tls_inspection', 'running');
    updateStage(job, 'threat_intel', 'running');
    updateStage(job, 'screenshot_capture', 'running');

    const dnsStart = Date.now();
    const tlsStart = Date.now();
    const intelStart = Date.now();
    const ssStart = Date.now();

    const finalHeaders = redirectRes.finalFetch?.headers ?? {};

    const dnsPromise = analyzeDomainAndDns(finalHost, finalHeaders).then((res) => {
      findings.push(...res.findings);
      if (res.data.rdapSource || res.data.whoisSource) recordProviderSuccess('rdap');
      if (res.data.dnsRecords.dohVerified) recordProviderSuccess('doh');
      updateStage(
        job,
        'domain_rdap',
        res.data.domainAgeDays === undefined ? 'warning' : 'completed',
        {
          en:
            res.data.domainAgeDays !== undefined
              ? `Age: ${res.data.domainAgeDays}d · ${res.data.dnsRecords.a.length} A`
              : `${res.data.dnsRecords.a.length} A record(s)`,
          ar: `فحص النطاق و DNS مكتمل`,
        },
        Date.now() - dnsStart
      );
      return res;
    });

    const tlsPromise = inspectTlsCertificate(redirectRes.finalUrl, finalPinnedIp).then((res) => {
      findings.push(...res.findings);
      if (res.data.ctSource) recordProviderSuccess('crtsh');
      updateStage(
        job,
        'tls_inspection',
        res.data.httpsAvailable && res.data.authorized && !res.data.expired ? 'completed' : 'warning',
        {
          en: res.data.httpsAvailable ? `${res.data.protocol ?? 'TLS'} · ${res.data.issuer ?? 'Verified'}` : 'No TLS endpoint',
          ar: 'اكتمل فحص شهادة TLS',
        },
        Date.now() - tlsStart
      );
      return res;
    });

    const isCdnEdgeHeader = Boolean(
      finalHeaders['cf-ray'] ||
        finalHeaders['x-amz-cf-id'] ||
        finalHeaders['x-vercel-id'] ||
        finalHeaders['x-served-by']?.includes('cache-') ||
        /cloudflare|fastly|akamai|cloudfront|vercel|netlify/i.test(finalHeaders['server'] || '')
    );

    const intelPromise = runExternalThreatIntel(
      redirectRes.finalUrl,
      finalHost,
      urlIntel.registrableDomain,
      options.disabledProviders ?? [],
      finalPinnedIp,
      isCdnEdgeHeader
    ).then((res) => {
      findings.push(...res.findings);
      const flagged = res.providers.filter((p) => p.status === 'flagged').length;
      updateStage(
        job,
        'threat_intel',
        flagged > 0 ? 'failed' : 'completed',
        {
          en: `${res.providers.filter((p) => p.status === 'clean' || p.status === 'flagged').length}/${res.providers.length} feeds responded`,
          ar: `استجاب مزودو التهديدات`,
        },
        Date.now() - intelStart
      );
      return res;
    });

    const screenshotPromise = captureWebsiteScreenshot(redirectRes.finalUrl, viewportMode).then((res) => {
      findings.push(res.finding);
      updateStage(
        job,
        'screenshot_capture',
        res.screenshot.status === 'captured' ? 'completed' : 'unavailable',
        {
          en: res.screenshot.status === 'captured' ? `Captured (${res.screenshot.viewport})` : 'Preview unavailable',
          ar: 'اكتملت المعاينة البصرية',
        },
        Date.now() - ssStart
      );
      return res;
    });

    const faviconPromise = fetchSiteFaviconSafely(
      redirectRes.finalUrl,
      redirectRes.finalFetch?.buffer,
      finalHeaders['content-type']
    ).catch(() => ({ dataUrl: undefined, sourceUrl: undefined }));

    const [dnsRes, tlsRes, intelRes, screenshotRes, faviconRes] = await Promise.all([
      dnsPromise,
      tlsPromise,
      intelPromise,
      screenshotPromise,
      faviconPromise,
    ]);

    // Domain Authenticity Verification (PSL + Official Registry + Live DNS/TLS/RDAP/ASN/OTX corroboration)
    const dnsResolved = dnsRes.data.dnsRecords.a.length > 0 || dnsRes.data.dnsRecords.aaaa.length > 0;
    const otxAllowlisted = intelRes.providers.some(
      (p) => p.providerId === 'otx' && /allowlist/i.test(p.verdictDetail.en)
    );
    const hasCoreDeception = Boolean(
      deceptionRes.data.confusableDetected ||
        deceptionRes.data.mixedScripts ||
        deceptionRes.data.bidiControlsDetected ||
        deceptionRes.data.zeroWidthDetected ||
        deceptionRes.data.authorityMasking ||
        deceptionRes.data.subdomainSpoofing ||
        deceptionRes.data.openRedirectConfirmed
    );
    const domainAuthenticity = assessDomainAuthenticity({
      hostname: finalHost,
      dnsResolved,
      dnsNameservers: dnsRes.data.nameservers,
      cdnOrProxyProvider: dnsRes.data.dnsRecords.cdnOrProxyProvider,
      rdapRegistrar: dnsRes.data.registrar,
      rdapOwner: dnsRes.data.ownerSummary.en,
      rdapRegistry: dnsRes.data.rdapSource || dnsRes.data.registry,
      asn: dnsRes.data.asn,
      networkName: dnsRes.data.networkName,
      tlsAuthorized: tlsRes.data.httpsAvailable ? tlsRes.data.authorized : false,
      tlsExpired: tlsRes.data.expired,
      tlsDomainMatches: tlsRes.data.domainMatches,
      tlsIssuer: tlsRes.data.issuer,
      otxAllowlisted,
      deceptionDetected: hasCoreDeception,
      similarityTarget: deceptionRes.data.typosquatTarget
        ? {
            brand: deceptionRes.data.typosquatTarget.brand,
            officialDomain: deceptionRes.data.typosquatTarget.officialDomain,
            reason: deceptionRes.data.typosquatTarget.technique,
          }
        : undefined,
    });

    // Stage: Risk Scoring & Correlation
    t0 = Date.now();
    updateStage(job, 'risk_scoring', 'running');
    const scored = computeRiskAndSections(findings, intelRes.providers, {
      domainAuthenticity,
      tlsData: tlsRes.data,
      dnsData: dnsRes.data,
      redirects: redirectRes.hops,
      finalUrl: redirectRes.finalUrl,
    });
    updateStage(
      job,
      'risk_scoring',
      'completed',
      {
        en: `Score ${scored.riskScore}/100 · ${scored.classification}`,
        ar: `النتيجة ${scored.riskScore}/100 · ${scored.classification}`,
      },
      Date.now() - t0
    );

    // Stage: Report Generation
    t0 = Date.now();
    updateStage(job, 'report_generation', 'running');

    const completedAt = new Date().toISOString();
    const suspectedBrandConfirmed = Boolean(
      contentRes.data?.suspectedBrand && !contentRes.data.suspectedBrand.similarityOnly
    );
    const report: ScanReport = {
      scanId: job.scanId,
      submittedUrl: options.url,
      normalizedUrl: validated.normalizedUrl,
      finalDestinationUrl: redirectRes.finalUrl,
      pageTitle: contentRes.data?.pageTitle || undefined,
      siteFaviconDataUrl: faviconRes.dataUrl,
      siteFaviconSourceUrl: faviconRes.sourceUrl,
      startedAt: job.startedAt,
      completedAt,
      durationMs: Date.now() - pipelineStart,
      status: scored.summaryStats.incompleteChecks > 0 ? 'partial' : 'completed',
      riskScore: scored.riskScore,
      classification: scored.classification,
      verdict: scored.verdict,
      confidenceScore: scored.confidenceScore,
      confidenceLabel: scored.confidenceLabel,
      recommendation: scored.recommendation,
      topReasons: scored.topReasons,
      correlationNotes: scored.correlationNotes,
      conflictNotes: scored.conflictNotes,
      domainAuthenticity: scored.domainAuthenticity,
      separatedAssessments: scored.separatedAssessments,
      summaryStats: scored.summaryStats,
      sections: scored.sections,
      findings,
      redirects: redirectRes.hops,
      domainDeception: deceptionRes.data,
      domainIntel: dnsRes.data,
      tlsIntel: tlsRes.data,
      contentIntel: contentRes.data,
      sourceIntel: sourceRes.sourceIntel,
      pageDiscovery: discoveryRes.pageDiscovery,
      formSecurityDetails: sourceRes.formDetails,
      supplyChain: sourceRes.supplyChain,
      visualIdentity: {
        attempted: true,
        screenshotAvailable: screenshotRes.screenshot.status === 'captured',
        brandMismatch: suspectedBrandConfirmed,
        titleMatchesBrandOutsideOfficial: false,
        faviconDetected: Boolean(faviconRes.dataUrl),
        similarityAssessment: {
          en: contentRes.data?.suspectedBrand
            ? contentRes.data.suspectedBrand.similarityOnly
              ? `Domain name similarity to ${contentRes.data.suspectedBrand.brand} (${contentRes.data.suspectedBrand.officialDomain}) detected; impersonation has not been proven.`
              : `Visual identity matches monitored brand "${contentRes.data.suspectedBrand.brand}" outside official domain.`
            : 'Visual identity telemetry verified.',
          ar: contentRes.data?.suspectedBrand
            ? contentRes.data.suspectedBrand.similarityOnly
              ? 'تم اكتشاف تشابه في اسم النطاق مع علامة تجارية معروفة، ولم يتم إثبات الانتحال.'
              : `تطابقت مؤشرات الهوية مع علامة "${contentRes.data.suspectedBrand.brand}" خارج النطاق الرسمي.`
            : 'تم التحقق من الهوية البصرية ومقارنتها بقاعدة البيانات.',
        },
        limitationNote: {
          en: 'Deterministic static heuristic comparison against known brand signatures; zero AI inference.',
          ar: 'مقارنة حتمية مع توقيعات العلامات التجارية دون أي استخدام للذكاء الاصطناعي.',
        },
      },
      fileAnalysis: {
        isDirectDownload: fileRes.isDirectDownload,
        directFile: fileRes.directFile,
        discoveredDownloads: fileRes.discoveredDownloads,
        dynamicAnalysisPerformed: false,
        sandboxNote: {
          en: 'Static header and magic-byte inspection only. No files executed.',
          ar: 'فحص التوقيع الساكن في الذاكرة فقط دون تشغيل أي ملفات.',
        },
      },
      threatProviders: intelRes.providers,
      screenshot: screenshotRes.screenshot,
      sandboxCapabilities: {
        ssrfGuardActive: true,
        isolatedBrowserWorker: false,
        screenshotFallbackConfigured: Boolean(process.env.SCREENSHOTNEO_ACCESS_KEY),
        dynamicFileSandbox: false,
        inspectionMode: 'controlled_server_fetch',
        disclosure: {
          en: 'SSRF network guard active. Static source inspection, multi-page crawling, TLS inspection, ScreenshotNeo preview gateway, and threat-feed correlation completed without executing target code locally.',
          ar: 'حماية SSRF مفعلة. تم إتمام فحص المصدر المتعدد الصفحات والتشفير ومعاينة ScreenshotNeo واستخبارات التهديدات دون تنفيذ أي أكواد محلياً.',
        },
      },
    };

    job.report = report;
    job.completedAt = completedAt;
    job.status = 'completed';
    updateStage(
      job,
      'report_generation',
      'completed',
      {
        en: `${scored.summaryStats.totalChecks} checks compiled in ${report.durationMs} ms`,
        ar: `تم تجميع ${scored.summaryStats.totalChecks} فحصاً خلال ${report.durationMs} مللي ثانية`,
      },
      Date.now() - t0
    );
    job.progressPercent = 100;
    jobEmitters.get(job.scanId)?.emit('update', job);
  } catch (err) {
    const message = (err as Error).message || 'Scan validation failed';
    updateStage(job, 'url_validation', 'failed', { en: message, ar: message });
    job.status = 'failed';
    job.completedAt = new Date().toISOString();
    job.error = { en: message, ar: message };
    jobEmitters.get(job.scanId)?.emit('update', job);
  }
}
