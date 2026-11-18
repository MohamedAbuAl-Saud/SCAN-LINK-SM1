import crypto from 'node:crypto';
import * as cheerio from 'cheerio';
import type { CheckFinding, FileDownloadItem } from '../types.ts';

const DANGEROUS_EXTENSIONS = new Set([
  '.exe', '.msi', '.bat', '.cmd', '.ps1', '.vbs', '.vbe', '.js', '.jse',
  '.wsf', '.scr', '.pif', '.com', '.hta', '.cpl', '.lnk', '.iso', '.img',
  '.apk', '.dmg', '.pkg', '.jar', '.docm', '.xlsm', '.pptm',
]);

const ARCHIVE_EXTENSIONS = new Set(['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2']);

function detectMagicSignature(buf: Buffer): { label: string; isExecutable: boolean } | undefined {
  if (buf.length < 4) return undefined;
  if (buf[0] === 0x4d && buf[1] === 0x5a) return { label: 'Windows PE Executable (MZ)', isExecutable: true };
  if (buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) {
    return { label: 'Linux ELF Executable', isExecutable: true };
  }
  if (buf.slice(0, 5).toString('ascii') === '%PDF-') return { label: 'PDF Document (%PDF-)', isExecutable: false };
  if (buf[0] === 0x50 && buf[1] === 0x4b && (buf[2] === 0x03 || buf[2] === 0x05)) {
    return { label: 'ZIP / OpenXML / APK Container (PK)', isExecutable: false };
  }
  if (buf[0] === 0x52 && buf[1] === 0x61 && buf[2] === 0x72 && buf[3] === 0x21) {
    return { label: 'RAR Archive', isExecutable: false };
  }
  if (buf.length >= 6 && buf[0] === 0x37 && buf[1] === 0x7a && buf[2] === 0xbc && buf[3] === 0xaf) {
    return { label: '7-Zip Archive', isExecutable: false };
  }
  if (buf[0] === 0x1f && buf[1] === 0x8b) return { label: 'GZIP Stream', isExecutable: false };
  return undefined;
}

function hasSuspiciousFilenamePattern(name: string): boolean {
  return /\.(pdf|doc|docx|xls|xlsx|jpg|png)\.(exe|scr|js|vbs|bat|ps1|zip|html?)$/i.test(name) ||
    /(invoice|payment|urgent|update|setup|crack|keygen|patch).*\.(exe|msi|zip|rar|apk|iso|scr|js)$/i.test(name);
}

export function analyzeFileAndDownloads(
  finalUrl: string,
  headers: Record<string, string>,
  rawBuffer: Buffer | undefined
): {
  isDirectDownload: boolean;
  directFile?: FileDownloadItem;
  discoveredDownloads: FileDownloadItem[];
  dynamicAnalysisPerformed: boolean;
  findings: CheckFinding[];
} {
  const now = new Date().toISOString();
  const findings: CheckFinding[] = [];
  const discoveredDownloads: FileDownloadItem[] = [];

  const contentType = (headers['content-type'] || '').split(';')[0].trim().toLowerCase();
  const contentDisp = headers['content-disposition'] || '';
  const contentLength = headers['content-length'] ? Number(headers['content-length']) : rawBuffer?.length;

  const parsedUrl = new URL(finalUrl);
  const pathBase = parsedUrl.pathname.split('/').pop() || '';
  const dispMatch = contentDisp.match(/filename\*?=(?:UTF-8'')?"?([^";\r\n]+)"?/i);
  const filename = dispMatch?.[1] || pathBase || 'download';
  const extMatch = filename.toLowerCase().match(/\.[a-z0-9]{1,8}$/)?.[0] || '';

  const isHtmlOrText =
    contentType.includes('text/html') ||
    contentType.includes('application/xhtml') ||
    contentType.includes('text/plain') ||
    contentType.includes('application/json');

  const isDirectDownload =
    contentDisp.toLowerCase().includes('attachment') ||
    DANGEROUS_EXTENSIONS.has(extMatch) ||
    ARCHIVE_EXTENSIONS.has(extMatch) ||
    (Boolean(contentType) && !isHtmlOrText && !contentType.startsWith('image/'));

  let directFile: FileDownloadItem | undefined;

  if (isDirectDownload && rawBuffer) {
    const inspectedSlice = rawBuffer.slice(0, 512 * 1024);
    const sha256 = crypto.createHash('sha256').update(inspectedSlice).digest('hex');
    const magic = detectMagicSignature(inspectedSlice);

    const isExeExt = DANGEROUS_EXTENSIONS.has(extMatch);
    const isArchive = ARCHIVE_EXTENSIONS.has(extMatch);
    const suspiciousNaming = hasSuspiciousFilenamePattern(filename);
    const mimeMismatch = Boolean(
      magic &&
        ((magic.isExecutable && !isExeExt) || (magic.label.startsWith('PDF') && extMatch && extMatch !== '.pdf'))
    );

    const riskFlag = magic?.isExecutable || isExeExt || mimeMismatch || suspiciousNaming ? 'high' : isArchive ? 'medium' : 'low';

    directFile = {
      url: finalUrl,
      filename,
      extension: extMatch || 'none',
      declaredMime: contentType || 'unknown',
      detectedSignature: magic?.label || 'Unrecognized / Stream',
      sizeBytes: contentLength,
      sha256,
      mimeMismatch,
      suspiciousNaming,
      analysisState: rawBuffer.length >= 2 * 1024 * 1024 ? 'blocked_size_limit' : 'header_inspected',
      riskFlag,
      notes: {
        en: 'Static header & SHA-256 inspected in memory only. Dynamic malware detonation was NOT performed.',
        ar: 'تم فحص الترويسة وبصمة SHA-256 في الذاكرة فقط. لم يتم إجراء تحليل سلوكي ديناميكي للملف.',
      },
    };

    findings.push({
      id: 'file-direct-download',
      section: 'file_download_analysis',
      test: { en: 'Direct File Signature & Hash Inspection', ar: 'فحص التوقيع الثنائي وبصمة الملف المباشر' },
      result: mimeMismatch
        ? { en: `MIME/Extension mismatch (${magic?.label} disguised as ${extMatch})`, ar: `تضارب في توقيع الملف (${magic?.label})` }
        : {
            en: `${filename} · SHA-256 computed · Dynamic detonation not performed`,
            ar: `${filename} · تم حساب SHA-256 · لم يُجرَ تشغيل ديناميكي`,
          },
      status: mimeMismatch || magic?.isExecutable || isExeExt || suspiciousNaming ? 'failed' : 'warning',
      severity: riskFlag,
      weight: mimeMismatch ? 28 : magic?.isExecutable || isExeExt || suspiciousNaming ? 24 : 8,
      evidence: `File: ${filename} | MIME: ${contentType} | Magic: ${magic?.label ?? 'N/A'} | SHA256: ${sha256}`,
      explanation: {
        en: 'Files are never executed or persisted to the application server. Because an isolated malware detonation sandbox is not connected, direct binaries remain not fully verified safe.',
        ar: 'لا يتم حفظ الملفات أو تشغيلها على الخادم؛ ونظراً لعدم ربط صندوق تفجير معزول، يبقى الملف غير متحقق من سلامته بالكامل.',
      },
      recommendedAction: {
        en: 'Do not open downloaded executables, scripts, or mismatched files on a production device.',
        ar: 'لا تقم بتشغيل الملفات التنفيذية أو السكربتات أو الملفات ذات التوقيع المتضارب.',
      },
      forensic: {
        whereDetected: { en: `Direct HTTP payload "${filename}" (${contentType})`, ar: `الاستجابة المباشرة للملف "${filename}"` },
        whyRisky: {
          en: 'Direct binary payloads or disguised executable headers bypass HTML-only scanners to compromise endpoints directly.',
          ar: 'الملفات التنفيذية المباشرة أو المزورة تتجاوز فحص الصفحات النصية لإصابة جهاز الضحية مباشرة.',
        },
        howExploited: {
          en: 'Trojans disguise EXEs/scripts as invoices or software updates using double extensions.',
          ar: 'تتنكر البرمجيات الخبيثة بأسماء فواتير أو تحديثات مع امتداد مزدوج.',
        },
        userImpact: { en: 'Ransomware, infostealers, or remote access trojan infection.', ar: 'إصابة الجهاز ببرمجيات فدية أو سرقة بيانات.' },
        notProvenAlone: {
          en: 'Legitimate software downloads also distribute executables/archives; trust requires verified publisher hash and code signing.',
          ar: 'توزيع برامج التثبيت أو الملفات المضغوطة قد يكون مشروعاً على المواقع الرسمية الموثوقة.',
        },
      },
      source: 'SM In-Memory File Inspector',
      timestamp: now,
      confidence: 88,
    });
  } else if (rawBuffer && isHtmlOrText) {
    const $ = cheerio.load(rawBuffer.toString('utf8'));
    const seen = new Set<string>();
    $('a[href]').each((_, el) => {
      const href = ($(el).attr('href') || '').trim();
      if (!href || href.startsWith('#') || href.startsWith('javascript:')) return;
      try {
        const resolved = new URL(href, finalUrl).toString();
        if (seen.has(resolved)) return;
        const p = new URL(resolved).pathname.toLowerCase();
        const ext = p.match(/\.[a-z0-9]{1,8}$/)?.[0] || '';
        const fname = p.split('/').pop() || 'file';
        if (DANGEROUS_EXTENSIONS.has(ext) || ARCHIVE_EXTENSIONS.has(ext) || $(el).attr('download') !== undefined) {
          seen.add(resolved);
          const isDanger = DANGEROUS_EXTENSIONS.has(ext) || hasSuspiciousFilenamePattern(fname);
          discoveredDownloads.push({
            url: resolved,
            filename: fname,
            extension: ext || 'unknown',
            mimeMismatch: false,
            suspiciousNaming: hasSuspiciousFilenamePattern(fname),
            analysisState: 'not_fully_analyzed',
            riskFlag: isDanger ? 'high' : 'medium',
            notes: {
              en: 'Linked downloadable resource detected in HTML; not downloaded or executed. Dynamic analysis not performed.',
              ar: 'تم رصد رابط تنزيل في الصفحة؛ لم يتم تنزيله أو تشغيله، ولم يُجرَ تحليل ديناميكي.',
            },
          });
        }
      } catch {
        // ignore
      }
    });

    const hasDangerousLink = discoveredDownloads.some((d) => d.riskFlag === 'high');
    findings.push({
      id: 'file-linked-downloads',
      section: 'file_download_analysis',
      test: { en: 'Linked Downloadable Resources Inspection', ar: 'فحص روابط التنزيل والملفات المضمنة' },
      result:
        discoveredDownloads.length > 0
          ? {
              en: `${discoveredDownloads.length} download link(s) detected (${discoveredDownloads.filter((d) => d.riskFlag === 'high').length} high-risk executable/macro)`,
              ar: `رصد ${discoveredDownloads.length} رابط تنزيل (${discoveredDownloads.filter((d) => d.riskFlag === 'high').length} عالي الخطورة)`,
            }
          : { en: 'No executable or archive download links detected', ar: 'لا توجد روابط تنزيل تنفيذية أو أرشيفية' },
      status: hasDangerousLink ? 'failed' : discoveredDownloads.length > 0 ? 'warning' : 'pass',
      severity: hasDangerousLink ? 'high' : discoveredDownloads.length > 0 ? 'medium' : 'informational',
      weight: hasDangerousLink ? 20 : discoveredDownloads.length > 0 ? 6 : 0,
      evidence:
        discoveredDownloads.length > 0
          ? discoveredDownloads.slice(0, 5).map((d) => `${d.filename} (${d.extension})`).join(' | ')
          : 'No risky download anchors found in HTML',
      explanation: {
        en:
          discoveredDownloads.length > 0
            ? 'Downloadable links were detected in the page HTML. Linked files are never executed or automatically fetched; dynamic malware analysis was not performed.'
            : 'No links pointing to executables, scripts, archives, or macro documents were found.',
        ar:
          discoveredDownloads.length > 0
            ? 'تم رصد روابط تنزيل داخل الصفحة؛ لا يتم تشغيل الملفات أو جلبها تلقائياً ولم يُجرَ تحليل ديناميكي.'
            : 'لم يتم العثور على روابط لملفات تنفيذية أو سكربتات أو مستندات ماكرو.',
      },
      recommendedAction: {
        en: discoveredDownloads.length > 0 ? 'Do not download or execute unverified executables or macro documents.' : 'No action required.',
        ar: discoveredDownloads.length > 0 ? 'لا تقم بتنزيل أو تشغيل ملفات تنفيذية أو مستندات ماكرو غير موثوقة.' : 'لا يلزم إجراء.',
      },
      source: 'SM HTML Download Scanner',
      timestamp: now,
      confidence: 88,
    });
  } else {
    findings.push({
      id: 'file-uninspected',
      section: 'file_download_analysis',
      test: { en: 'File & Download Analysis', ar: 'تحليل الملفات والتنزيلات' },
      result: { en: 'Not Fully Analyzed (no response payload)', ar: 'لم يُحلل بالكامل (لا يوجد محتوى)' },
      status: 'unknown',
      severity: 'unknown',
      weight: 0,
      evidence: 'No response body retrieved',
      explanation: {
        en: 'No response payload was retrieved; dynamic file analysis was not performed.',
        ar: 'تعذر استرجاع المحتوى للفحص ولم يتم إجراء تحليل ديناميكي.',
      },
      recommendedAction: {
        en: 'Treat unretrieved files as unverified.',
        ar: 'اعتبر الملفات التي تعذر جلبها غير متحقق منها.',
      },
      source: 'SM In-Memory File Inspector',
      timestamp: now,
      confidence: 20,
    });
  }

  return {
    isDirectDownload,
    directFile,
    discoveredDownloads: discoveredDownloads.slice(0, 15),
    dynamicAnalysisPerformed: false,
    findings,
  };
}
