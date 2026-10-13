import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

// Core logic models matching frontend implementation
interface InstalledAppInfo {
  packageName: string;
  appName: string;
  versionName: string;
  isSystem: boolean;
  isSplit: boolean;
  splitCount: number;
  apkSize: number;
  icon?: string | null;
}

// Helper functions mirroring frontend logic in App.tsx
function validateApkFile(filename: string): { valid: boolean; error?: string } {
  const lower = filename.toLowerCase();
  if (!lower.endsWith('.apk') && !lower.endsWith('.zip')) {
    return {
      valid: false,
      error: 'Invalid file type. Please select a valid Android APK package (.apk).'
    };
  }
  return { valid: true };
}

function formatBytes(bytes: number): string {
  if (bytes <= 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

function filterApps(apps: InstalledAppInfo[], query: string, includeSystem: boolean): InstalledAppInfo[] {
  return apps
    .filter(a => includeSystem || !a.isSystem)
    .filter(a => {
      if (!query.trim()) return true;
      const q = query.toLowerCase();
      return a.appName.toLowerCase().includes(q) || a.packageName.toLowerCase().includes(q);
    });
}

function isDesktopBrowser(bridge: any): boolean {
  return !bridge;
}

describe('Frontend APK Selection & Validation', () => {
  it('accepts valid APK and ZIP files', () => {
    assert.equal(validateApkFile('app-debug.apk').valid, true);
    assert.equal(validateApkFile('MY_APP.APK').valid, true);
    assert.equal(validateApkFile('backup.zip').valid, true);
  });

  it('rejects invalid file types with descriptive error', () => {
    const pdfRes = validateApkFile('document.pdf');
    assert.equal(pdfRes.valid, false);
    assert.equal(pdfRes.error, 'Invalid file type. Please select a valid Android APK package (.apk).');

    assert.equal(validateApkFile('malware.exe').valid, false);
    assert.equal(validateApkFile('photo.png').valid, false);
    assert.equal(validateApkFile('source.tar.gz').valid, false);
  });

  it('correctly formats byte sizes for mobile UI display', () => {
    assert.equal(formatBytes(0), '0 B');
    assert.equal(formatBytes(1024), '1 KB');
    assert.equal(formatBytes(5242880), '5 MB');
    assert.equal(formatBytes(157286400), '150 MB');
  });
});

describe('Installed Application Discovery & Filtering', () => {
  const sampleApps: InstalledAppInfo[] = [
    {
      packageName: 'com.spyware.tracker',
      appName: 'Covert Tracker',
      versionName: '1.0',
      isSystem: false,
      isSplit: false,
      splitCount: 0,
      apkSize: 15000000
    },
    {
      packageName: 'com.android.settings',
      appName: 'Settings',
      versionName: '14.0',
      isSystem: true,
      isSplit: true,
      splitCount: 2,
      apkSize: 45000000
    },
    {
      packageName: 'com.social.messenger',
      appName: 'Social Chat',
      versionName: '2.5.1',
      isSystem: false,
      isSplit: true,
      splitCount: 4,
      apkSize: 85000000
    },
    {
      packageName: 'com.android.systemui',
      appName: 'System UI',
      versionName: '14.0',
      isSystem: true,
      isSplit: false,
      splitCount: 0,
      apkSize: 32000000
    }
  ];

  it('filters out system apps by default', () => {
    const userApps = filterApps(sampleApps, '', false);
    assert.equal(userApps.length, 2);
    assert.equal(userApps[0].packageName, 'com.spyware.tracker');
    assert.equal(userApps[1].packageName, 'com.social.messenger');
    assert.ok(userApps.every(a => !a.isSystem));
  });

  it('includes system apps when toggle is enabled', () => {
    const allApps = filterApps(sampleApps, '', true);
    assert.equal(allApps.length, 4);
    assert.ok(allApps.some(a => a.isSystem));
  });

  it('searches apps case-insensitively by app name', () => {
    const result = filterApps(sampleApps, 'tracker', false);
    assert.equal(result.length, 1);
    assert.equal(result[0].appName, 'Covert Tracker');
  });

  it('searches apps case-insensitively by package name', () => {
    const result = filterApps(sampleApps, 'com.social', false);
    assert.equal(result.length, 1);
    assert.equal(result[0].packageName, 'com.social.messenger');
  });

  it('returns empty list when search does not match', () => {
    const result = filterApps(sampleApps, 'nonexistent_package', false);
    assert.equal(result.length, 0);
  });

  it('identifies split APK installations correctly', () => {
    const splitApp = sampleApps.find(a => a.packageName === 'com.social.messenger');
    assert.ok(splitApp);
    assert.equal(splitApp.isSplit, true);
    assert.equal(splitApp.splitCount, 4);

    const nonSplitApp = sampleApps.find(a => a.packageName === 'com.spyware.tracker');
    assert.ok(nonSplitApp);
    assert.equal(nonSplitApp.isSplit, false);
    assert.equal(nonSplitApp.splitCount, 0);
  });
});

describe('Desktop Browser Fallback & Native Bridge Integration', () => {
  it('detects desktop browser mode when window.SpyAwareBridge is absent', () => {
    assert.equal(isDesktopBrowser(undefined), true);
    assert.equal(isDesktopBrowser(null), true);
  });

  it('detects native Android wrapper when window.SpyAwareBridge is present', () => {
    const mockBridge = {
      isNativeWrapper: () => true,
      getBackendUrl: () => 'http://10.0.2.2:8000',
      getInstalledApps: () => '[]',
      analyzeInstalledApp: () => {}
    };
    assert.equal(isDesktopBrowser(mockBridge), false);
  });

  it('handles native upload progress and analysis callbacks properly', async () => {
    let currentStage = '';
    let currentPercent = 0;
    let receivedReport: any = null;
    let receivedError: string | null = null;

    const onProgress = (p: { percent: number; stage: string }) => {
      currentPercent = p.percent;
      currentStage = p.stage;
    };

    const onSuccess = (report: any) => {
      receivedReport = report;
    };

    const onError = (err: string) => {
      receivedError = err;
    };

    // Simulate progress updates
    onProgress({ percent: 15, stage: 'Resolving APK on device...' });
    assert.equal(currentPercent, 15);
    assert.equal(currentStage, 'Resolving APK on device...');

    onProgress({ percent: 65, stage: 'Streaming APK to backend (15MB/25MB)...' });
    assert.equal(currentPercent, 65);

    // Simulate analysis success
    const mockReport = {
      analysis_id: 'test-uuid-1234',
      overall_score: 88.5,
      risk_level: 'CRITICAL',
      apk_filename: 'com.spyware.tracker.apk',
      summary: 'High risk surveillance indicators detected.',
      findings: []
    };
    onSuccess(mockReport);
    assert.ok(receivedReport);
    assert.equal(receivedReport.risk_level, 'CRITICAL');
    assert.equal(receivedReport.analysis_id, 'test-uuid-1234');

    // Simulate error scenario
    onError('Connection refused to backend at http://10.0.2.2:8000');
    assert.equal(receivedError, 'Connection refused to backend at http://10.0.2.2:8000');
  });
});

describe('Frontend API URL Resolution & 150MB Limit', () => {
  it('resolves API URLs with backend prefix when bridge is available', () => {
    function resolveApiUrl(path: string, base: string): string {
      const b = base.replace(/\/+$/, '');
      const p = path.startsWith('/') ? path : `/${path}`;
      return b ? `${b}${p}` : p;
    }
    assert.equal(resolveApiUrl('/api/analyze', 'http://192.168.1.100:8000'), 'http://192.168.1.100:8000/api/analyze');
    assert.equal(resolveApiUrl('/api/dynamic/environment', 'http://10.0.2.2:8000/'), 'http://10.0.2.2:8000/api/dynamic/environment');
    assert.equal(resolveApiUrl('/api/analyze', ''), '/api/analyze');
  });

  it('accepts files up to 150MB and rejects files larger than 150MB', () => {
    function validateSize(bytes: number): { valid: boolean; error?: string } {
      if (bytes > 150 * 1024 * 1024) {
        return { valid: false, error: 'Selected file is too large' };
      }
      return { valid: true };
    }
    assert.equal(validateSize(50 * 1024 * 1024).valid, true);
    assert.equal(validateSize(100 * 1024 * 1024).valid, true);
    assert.equal(validateSize(150 * 1024 * 1024).valid, true);
    assert.equal(validateSize(151 * 1024 * 1024).valid, false);
  });
});

describe('Milestone M3 Desktop ADB Integration & Metadata Formatting', () => {
  it('maps backend discovered ADB packages to frontend InstalledAppInfo', () => {
    const rawDiscovered = [
      {
        package_name: 'com.example.deviceapp',
        app_name: 'Device App',
        version_name: '2.1.0',
        version_code: '42',
        is_system: false,
        is_split: true,
        split_count: 2,
        apk_size_bytes: 24500000
      },
      {
        package_name: 'com.android.providers.media',
        app_name: null,
        version_name: null,
        is_system: true,
        is_split: false,
        split_count: 0,
        apk_size_bytes: 8200000
      }
    ];

    const mapped: InstalledAppInfo[] = rawDiscovered.map(pkg => ({
      packageName: pkg.package_name,
      appName: pkg.app_name || pkg.package_name,
      versionName: pkg.version_name || '1.0',
      isSystem: Boolean(pkg.is_system),
      isSplit: Boolean(pkg.is_split),
      splitCount: pkg.split_count || 0,
      apkSize: pkg.apk_size_bytes || 0,
    }));

    assert.equal(mapped.length, 2);
    assert.equal(mapped[0].appName, 'Device App');
    assert.equal(mapped[0].isSplit, true);
    assert.equal(mapped[0].splitCount, 2);
    assert.equal(mapped[1].appName, 'com.android.providers.media'); // falls back to package_name
    assert.equal(mapped[1].versionName, '1.0'); // default fallback
    assert.equal(mapped[1].isSystem, true);
  });

  it('formats finding confidence scores as percentage strings', () => {
    function formatConfidence(conf?: number | null): string {
      if (conf === undefined || conf === null) return '';
      return `${Math.round(conf * 100)}% confidence`;
    }

    assert.equal(formatConfidence(0.95), '95% confidence');
    assert.equal(formatConfidence(0.5), '50% confidence');
    assert.equal(formatConfidence(1.0), '100% confidence');
    assert.equal(formatConfidence(null), '');
    assert.equal(formatConfidence(undefined), '');
  });

  it('constructs markdown export URLs properly with base URL', () => {
    function getMarkdownExportUrl(analysisId: string, base: string): string {
      const b = base.replace(/\/+$/, '');
      const path = `/api/analysis/${analysisId}/export/markdown`;
      return b ? `${b}${path}` : path;
    }

    assert.equal(
      getMarkdownExportUrl('test-uuid-1234', 'http://127.0.0.1:8000'),
      'http://127.0.0.1:8000/api/analysis/test-uuid-1234/export/markdown'
    );
    assert.equal(
      getMarkdownExportUrl('test-uuid-1234', ''),
      '/api/analysis/test-uuid-1234/export/markdown'
    );
  });
});

