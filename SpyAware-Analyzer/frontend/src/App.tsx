import React, { useState, useEffect } from 'react';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  AlertCircle,
  HelpCircle,
  UploadCloud,
  FileCode,
  RefreshCw,
  Cpu,
  Radio,
  Network,
  Search,
  Layers,
  Terminal,
  Activity,
  ChevronRight,
  Lock,
  Smartphone,
  Eye,
  Sliders,
  FileText,
  CheckCircle,
  XCircle,
  Clock,
  Camera,
  Mic,
  MapPin,
  MessageSquare,
  PhoneCall,
  Wifi,
  Globe,
  Unlock,
  Repeat,
  ArrowUpRight,
  Download
} from 'lucide-react';
import type { RiskReport, Severity, EnvironmentStatus, RuntimeObservation, InstalledAppInfo } from './types';

// Demo sample presets available in backend samples/
const PRESET_SAMPLES = [
  {
    id: 'benign_sample',
    name: 'Benign Sample App',
    category: 'Standard Utility',
    expected: 'LOW Risk (~3 pts)',
    badgeColor: 'text-emerald-700 bg-emerald-50 border-emerald-200'
  },
  {
    id: 'suspicious_surveillance_sample',
    name: 'Suspicious Surveillance App',
    category: 'Covert Monitor',
    expected: 'HIGH / CRITICAL Risk (~88 pts)',
    badgeColor: 'text-amber-700 bg-amber-50 border-amber-200'
  },
  {
    id: 'critical_stalkerware_sample',
    name: 'Critical Stalkerware App',
    category: 'Invasive Spyware',
    expected: 'CRITICAL Risk (~92 pts)',
    badgeColor: 'text-rose-700 bg-rose-50 border-rose-200'
  },
  {
    id: 'network_positive_sample',
    name: 'Network Positive Sample',
    category: 'Socket Telemetry',
    expected: 'ATTRIBUTED Network (~40 pts)',
    badgeColor: 'text-blue-700 bg-blue-50 border-blue-200'
  }
];

const NETWORK_BEHAVIOR_CATEGORIES: { id: string; label: string; icon: any; defaultSource: string; fallbackDesc: string }[] = [
  { id: 'NETWORK_CONNECTION', label: 'Network Sockets (TCP/UDP)', icon: Wifi, defaultSource: '/proc/net/tcp', fallbackDesc: 'Evaluates verified UID socket ownership on device.' },
  { id: 'DNS_ACTIVITY', label: 'DNS Resolution Activity', icon: Globe, defaultSource: 'port 53 / getprop', fallbackDesc: 'Monitors DNS socket operations and system resolver interactions.' },
  { id: 'CLEAR_TEXT_HTTP', label: 'Cleartext HTTP (Port 80/8080)', icon: Unlock, defaultSource: '/proc/net/tcp', fallbackDesc: 'Identifies unencrypted HTTP traffic carrying plaintext surveillance data.' },
  { id: 'EXTERNAL_DESTINATION', label: 'External / Gateway Destinations', icon: ArrowUpRight, defaultSource: '/proc/net/tcp', fallbackDesc: 'Audits non-loopback network destinations contacted at runtime.' },
  { id: 'REPEATED_CONNECTION', label: 'Repeated Connections / Beaconing', icon: Repeat, defaultSource: '/proc/net/tcp', fallbackDesc: 'Detects multiple connection attempts characteristic of C2 heartbeat polling.' },
  { id: 'UNUSUAL_PORT', label: 'Non-Standard Network Ports', icon: AlertTriangle, defaultSource: '/proc/net/tcp', fallbackDesc: 'Flags connections to non-standard ports outside web protocols (80, 443, 8080, 53).' },
];

const RUNTIME_BEHAVIOR_CATEGORIES: { id: string; label: string; icon: any; defaultSource: string; fallbackDesc: string }[] = [
  { id: 'CAMERA', label: 'Camera / Video Capture', icon: Camera, defaultSource: 'dumpsys media.camera', fallbackDesc: 'Monitors dumpsys media.camera and CameraManager runtime client connections.' },
  { id: 'MICROPHONE', label: 'Microphone / Audio Capture', icon: Mic, defaultSource: 'dumpsys audio', fallbackDesc: 'Monitors dumpsys audio for active AudioRecord and MediaRecorder sessions.' },
  { id: 'LOCATION', label: 'Location Tracking (GPS / Network)', icon: MapPin, defaultSource: 'dumpsys location', fallbackDesc: 'Monitors dumpsys location active provider requests and geofence listeners.' },
  { id: 'ACCESSIBILITY', label: 'Accessibility Service Abuse', icon: Eye, defaultSource: 'dumpsys accessibility', fallbackDesc: 'Monitors dumpsys accessibility for active bound services capturing user UI events.' },
  { id: 'MEDIA_PROJECTION', label: 'Screen Capture / MediaProjection', icon: Smartphone, defaultSource: 'dumpsys media_projection', fallbackDesc: 'Monitors dumpsys media_projection for active screen mirroring tokens.' },
  { id: 'SMS', label: 'SMS Telephony & Interception', icon: MessageSquare, defaultSource: 'logcat / telephony', fallbackDesc: 'Monitors logcat for runtime SmsManager transmissions or incoming intercept broadcasts.' },
  { id: 'CALL', label: 'Call Activity & Telephony', icon: PhoneCall, defaultSource: 'logcat / telephony', fallbackDesc: 'Monitors logcat and telephony services for active call state observation or recording.' },
  { id: 'BACKGROUND_SERVICE', label: 'Active Background Services', icon: Cpu, defaultSource: 'dumpsys activity services', fallbackDesc: 'Monitors dumpsys activity services for actively running ServiceRecords.' },
  { id: 'PERSISTENCE', label: 'Persistence & Boot Receivers', icon: RefreshCw, defaultSource: 'dumpsys / logcat', fallbackDesc: 'Monitors runtime boot event handlers, JobScheduler tasks, and alarms.' },
  { id: 'PROCESS', label: 'Runtime Process Lifecycle', icon: Activity, defaultSource: 'ps -A / proc', fallbackDesc: 'Monitors Linux process table (ps -A) and package UID activity.' },
];

export function getApiBaseUrl(): string {
  if (typeof window !== 'undefined' && window.__SPYAWARE_API_BASE__) {
    return window.__SPYAWARE_API_BASE__.replace(/\/+$/, '');
  }
  if (typeof window !== 'undefined' && window.SpyAwareBridge?.getBackendUrl) {
    try {
      const bridgeUrl = window.SpyAwareBridge.getBackendUrl();
      if (bridgeUrl && bridgeUrl.trim().length > 0) {
        return bridgeUrl.trim().replace(/\/+$/, '');
      }
    } catch {
      // ignore
    }
  }
  if (typeof window !== 'undefined' && window.location?.search) {
    try {
      const params = new URLSearchParams(window.location.search);
      const backendParam = params.get('backend');
      if (backendParam && backendParam.trim().length > 0) {
        return backendParam.trim().replace(/\/+$/, '');
      }
    } catch {
      // ignore
    }
  }
  if (typeof window !== 'undefined' && window.localStorage) {
    try {
      const stored = localStorage.getItem('spyaware_backend_url');
      if (stored && stored.trim().length > 0) {
        return stored.trim().replace(/\/+$/, '');
      }
    } catch {
      // ignore
    }
  }
  return '';
}

export function apiUrl(path: string): string {
  const base = getApiBaseUrl();
  const normalized = path.startsWith('/') ? path : `/${path}`;
  return base ? `${base}${normalized}` : normalized;
}

export function getModuleStatusBadge(rawStatus?: string | null): {
  label: string;
  badgeClass: string;
  icon: React.ReactElement;
  category: 'Completed' | 'Failed' | 'Inconclusive' | 'Skipped';
} {
  const status = (rawStatus || 'NOT_REQUESTED').toUpperCase();
  if (status === 'COMPLETED' || status === 'COMPLETED_CLEAN' || status === 'COMPLETED_WITH_FINDINGS' || status === 'NOT_ATTRIBUTED') {
    return {
      label: status === 'NOT_ATTRIBUTED' ? 'COMPLETED (NO TRAFFIC)' : 'COMPLETED',
      badgeClass: 'bg-emerald-50 text-emerald-700 border-emerald-200',
      icon: <CheckCircle className="w-3.5 h-3.5 text-emerald-600 shrink-0" />,
      category: 'Completed'
    };
  }
  if (status === 'FAILED' || status === 'INSTALLATION_FAILED' || status === 'LAUNCH_FAILED' || status === 'CAPTURE_FAILED') {
    return {
      label: status.replace(/_/g, ' '),
      badgeClass: 'bg-rose-50 text-rose-700 border-rose-200',
      icon: <XCircle className="w-3.5 h-3.5 text-rose-600 shrink-0" />,
      category: 'Failed'
    };
  }
  if (
    status === 'UNAVAILABLE' ||
    status === 'INCONCLUSIVE' ||
    status === 'TIMEOUT' ||
    status === 'NO_LAUNCHABLE_ACTIVITY' ||
    status === 'INCOMPATIBLE_ABI' ||
    status === 'EMULATOR_UNAVAILABLE' ||
    status === 'RUNTIME_UNAVAILABLE'
  ) {
    return {
      label: status === 'NO_LAUNCHABLE_ACTIVITY'
        ? 'INCONCLUSIVE (NO ACTIVITY)'
        : status === 'INCOMPATIBLE_ABI'
        ? 'UNAVAILABLE (INCOMPATIBLE ABI)'
        : status.replace(/_/g, ' '),
      badgeClass: 'bg-amber-50 text-amber-700 border-amber-200',
      icon: <AlertTriangle className="w-3.5 h-3.5 text-amber-600 shrink-0" />,
      category: 'Inconclusive'
    };
  }
  return {
    label: 'SKIPPED',
    badgeClass: 'bg-slate-100 text-slate-600 border-slate-200',
    icon: <Clock className="w-3.5 h-3.5 text-slate-400 shrink-0" />,
    category: 'Skipped'
  };
}

export function App() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisStage, setAnalysisStage] = useState('');
  const [report, setReport] = useState<RiskReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'static' | 'permissions' | 'dynamic' | 'network' | 'findings' | 'evidence'>('overview');
  const [findingSeverityFilter, setFindingSeverityFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [runDynamic, setRunDynamic] = useState<boolean>(false);
  const [runNetwork, setRunNetwork] = useState<boolean>(false);
  const [envStatus, setEnvStatus] = useState<EnvironmentStatus | null>(null);

  // Upload method selection: 'file' (Choose APK) vs 'installed' (Select Installed App)
  const [uploadMode, setUploadMode] = useState<'file' | 'installed'>('file');
  const [installedApps, setInstalledApps] = useState<InstalledAppInfo[]>([]);
  const [isLoadingApps, setIsLoadingApps] = useState(false);
  const [includeSystemApps, setIncludeSystemApps] = useState(false);
  const [appSearchQuery, setAppSearchQuery] = useState('');
  const [selectedApp, setSelectedApp] = useState<InstalledAppInfo | null>(null);
  const [uploadPercent, setUploadPercent] = useState<number>(0);
  const [connectedDevices, setConnectedDevices] = useState<any[]>([]);
  const [selectedDeviceSerial, setSelectedDeviceSerial] = useState<string>('');

  const isBridgeAvailable = typeof window !== 'undefined' && Boolean(window.SpyAwareBridge);

  interface ExternalModuleInfo {
    id: string;
    displayName: string;
    subtitle: string;
    packageName: string;
    isInstalled: boolean;
    description: string;
  }

  const [externalModules, setExternalModules] = useState<ExternalModuleInfo[]>([]);

  const refreshExternalModules = () => {
    try {
      if (typeof window !== 'undefined' && window.SpyAwareBridge?.getModulesJson) {
        const json = window.SpyAwareBridge.getModulesJson();
        if (json) {
          const list: ExternalModuleInfo[] = JSON.parse(json);
          setExternalModules(list);
        }
      }
    } catch (e) {
      console.warn('Failed to parse modules from bridge:', e);
    }
  };

  useEffect(() => {
    refreshExternalModules();
    const onFocus = () => refreshExternalModules();
    window.addEventListener('focus', onFocus);
    return () => window.removeEventListener('focus', onFocus);
  }, []);

  const mod4 = externalModules.find(m => m.id === 'module_4' || m.packageName === 'com.spyaware.network');
  const mod5 = externalModules.find(m => m.id === 'module_5' || m.packageName === 'com.example.spyaware');
  const isMod4Installed = mod4?.isInstalled ?? false;
  const isMod5Installed = mod5?.isInstalled ?? false;

  const handleLaunchModule = (pkgOrId: string) => {
    if (typeof window !== 'undefined' && window.SpyAwareBridge?.openModule) {
      window.SpyAwareBridge.openModule(pkgOrId);
    } else {
      alert(`Module '${pkgOrId}' can be launched or installed via the SpyAware Android app wrapper.`);
    }
  };

  const handleOpenAnalyzer = () => {
    const el = document.getElementById('analyzer-upload-panel') || document.querySelector('section[aria-label="Upload Panel"]');
    if (el) {
      el.scrollIntoView({ behavior: 'smooth' });
    } else {
      window.scrollTo({ top: 350, behavior: 'smooth' });
    }
  };

  const formatBytes = (bytes: number): string => {
    if (bytes <= 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
  };

  const loadInstalledApps = async (includeSystem: boolean) => {
    setIsLoadingApps(true);
    setError(null);
    await new Promise(r => setTimeout(r, 50));
    try {
      if (window.SpyAwareBridge?.getInstalledApps) {
        const raw = window.SpyAwareBridge.getInstalledApps(includeSystem);
        const list: InstalledAppInfo[] = JSON.parse(raw);
        setInstalledApps(list);
      } else {
        // Desktop browser mode: query backend ADB device discovery
        const devRes = await fetch(apiUrl('/api/devices'));
        if (!devRes.ok) {
          throw new Error(`Failed to query connected devices (HTTP ${devRes.status})`);
        }
        const devices = await devRes.json();
        setConnectedDevices(devices);
        if (!devices || devices.length === 0) {
          setError('No ADB devices or emulators connected. Ensure an emulator is running or a device is connected with USB debugging.');
          setInstalledApps([]);
          return;
        }
        const targetSerial = selectedDeviceSerial || devices[0]?.serial;
        if (targetSerial) {
          setSelectedDeviceSerial(targetSerial);
          const pkgRes = await fetch(apiUrl(`/api/devices/${encodeURIComponent(targetSerial)}/packages?include_system=${includeSystem}`));
          if (!pkgRes.ok) {
            throw new Error(`Failed to list packages on ${targetSerial} (HTTP ${pkgRes.status})`);
          }
          const packages = await pkgRes.json();
          const mapped: InstalledAppInfo[] = (packages || []).map((pkg: any) => ({
            packageName: pkg.package_name,
            appName: pkg.app_name || pkg.package_name,
            versionName: pkg.version_name || '1.0',
            isSystem: Boolean(pkg.is_system),
            isSplit: Boolean(pkg.is_split),
            splitCount: pkg.split_count || 0,
            apkSize: pkg.apk_size_bytes || 0,
            icon: null,
          }));
          setInstalledApps(mapped);
        }
      }
    } catch (err: any) {
      setError('Failed to enumerate installed applications: ' + (err.message || 'Discovery error'));
    } finally {
      setIsLoadingApps(false);
    }
  };

  // Manual permissions sandbox modal/toggle
  const [showPermSandbox, setShowPermSandbox] = useState(false);
  const [manualPermsInput, setManualPermsInput] = useState(
    'android.permission.CAMERA\nandroid.permission.RECORD_AUDIO\nandroid.permission.ACCESS_FINE_LOCATION\nandroid.permission.RECEIVE_BOOT_COMPLETED\nandroid.permission.INTERNET'
  );

  // Query environment readiness on mount
  useEffect(() => {
    fetch(apiUrl('/api/dynamic/environment'))
      .then(res => res.json())
      .then((data: EnvironmentStatus) => setEnvStatus(data))
      .catch(() => setEnvStatus(null));
  }, []);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      const lower = file.name.toLowerCase();
      if (!lower.endsWith('.apk') && !lower.endsWith('.zip')) {
        setError('Invalid file type. Please select a valid Android APK package (.apk).');
        setSelectedFile(null);
        return;
      }
      if (file.size > 150 * 1024 * 1024) {
        setError(`Selected file is too large (${(file.size / (1024 * 1024)).toFixed(1)} MB). SpyAware Analyzer accepts APK files up to 150 MB.`);
        setSelectedFile(null);
        return;
      }
      setSelectedFile(file);
      setError(null);
    }
  };

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      const lower = file.name.toLowerCase();
      if (!lower.endsWith('.apk') && !lower.endsWith('.zip')) {
        setError('Invalid file type. Please select a valid Android APK package (.apk).');
        setSelectedFile(null);
        return;
      }
      if (file.size > 150 * 1024 * 1024) {
        setError(`Selected file is too large (${(file.size / (1024 * 1024)).toFixed(1)} MB). SpyAware Analyzer accepts APK files up to 150 MB.`);
        setSelectedFile(null);
        return;
      }
      setSelectedFile(file);
      setError(null);
    }
  };

  const startInstalledAppAnalysis = async (app: InstalledAppInfo) => {
    setIsAnalyzing(true);
    setError(null);
    setUploadPercent(5);
    setAnalysisStage(`Preparing ${app.appName} on device...`);

    if (window.SpyAwareBridge?.analyzeInstalledApp) {
      window.onNativeUploadProgress = (p) => {
        setUploadPercent(p.percent);
        setAnalysisStage(p.stage);
      };

      window.onNativeAnalysisSuccess = (data: RiskReport) => {
        setReport(data);
        setIsAnalyzing(false);
        setAnalysisStage('');
        setUploadPercent(100);
        if (runNetwork && data.network_details && !runDynamic) {
          setActiveTab('network');
        } else if (runDynamic && data.dynamic_details) {
          setActiveTab('dynamic');
        } else {
          setActiveTab('overview');
        }
      };

      window.onNativeAnalysisError = (errMessage: string) => {
        setError(errMessage || 'Analysis failed on installed application');
        setIsAnalyzing(false);
        setAnalysisStage('');
        setUploadPercent(0);
      };

      window.SpyAwareBridge.analyzeInstalledApp(app.packageName, runDynamic, runNetwork);
    } else {
      // Desktop browser mode: invoke backend package extraction and analysis
      try {
        const serial = selectedDeviceSerial || (connectedDevices[0]?.serial) || 'emulator-5554';
        setUploadPercent(20);
        setAnalysisStage(`Extracting ${app.packageName} from device ${serial}...`);
        const res = await fetch(
          apiUrl(`/api/devices/${encodeURIComponent(serial)}/packages/${encodeURIComponent(app.packageName)}/analyze?dynamic=${runDynamic}&network=${runNetwork}`),
          { method: 'POST' }
        );
        if (!res.ok) {
          const errData = await res.json().catch(() => ({}));
          throw new Error(errData.detail || `Server returned HTTP ${res.status}`);
        }
        setUploadPercent(85);
        setAnalysisStage('Finalizing analysis report...');
        const data: RiskReport = await res.json();
        setReport(data);
        setIsAnalyzing(false);
        setAnalysisStage('');
        setUploadPercent(100);
        if (runNetwork && data.network_details && !runDynamic) {
          setActiveTab('network');
        } else if (runDynamic && data.dynamic_details) {
          setActiveTab('dynamic');
        } else {
          setActiveTab('overview');
        }
      } catch (err: any) {
        setError(err.message || 'Analysis failed on installed application');
        setIsAnalyzing(false);
        setAnalysisStage('');
        setUploadPercent(0);
      }
    }
  };

  const cancelInstalledAnalysis = () => {
    if (window.SpyAwareBridge?.cancelAnalysis) {
      window.SpyAwareBridge.cancelAnalysis();
    }
    setIsAnalyzing(false);
    setAnalysisStage('');
    setUploadPercent(0);
  };

  const runAnalysis = async (fileToAnalyze: File) => {
    setIsAnalyzing(true);
    setError(null);
    setAnalysisStage('Uploading APK package...');

    const formData = new FormData();
    formData.append('file', fileToAnalyze);

    try {
      setAnalysisStage('Decompressing archive & parsing AndroidManifest.xml...');
      await new Promise(r => setTimeout(r, 300));
      setAnalysisStage('Inspecting DEX bytecode API signatures & native libraries...');
      await new Promise(r => setTimeout(r, 300));
      setAnalysisStage('Evaluating SpyAware surveillance combination rules...');

      if (runDynamic) {
        setAnalysisStage('Executing in headless Android emulator sandbox (Stage 2B Behavioral)...');
      } else if (runNetwork) {
        setAnalysisStage('Auditing Android kernel socket states & UID attribution (Stage 2C)...');
      }

      const params = new URLSearchParams();
      if (runDynamic) params.append('dynamic', 'true');
      if (runNetwork) params.append('network', 'true');
      const url = apiUrl(params.toString() ? `/api/analyze?${params.toString()}` : '/api/analyze');

      const response = await fetch(url, {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({ detail: 'Analysis failed' }));
        throw new Error(errData.detail || `Server returned ${response.status}`);
      }

      const data: RiskReport = await response.json();
      setReport(data);
      if (runNetwork && data.network_details && !runDynamic) {
        setActiveTab('network');
      } else if (runDynamic && data.dynamic_details) {
        setActiveTab('dynamic');
      } else {
        setActiveTab('overview');
      }
    } catch (err: any) {
      setError(err.message || 'An error occurred during analysis');
    } finally {
      setIsAnalyzing(false);
      setAnalysisStage('');
    }
  };

  const runPresetAnalysis = async (presetId: string) => {
    setIsAnalyzing(true);
    setError(null);
    setSelectedFile(null);
    setAnalysisStage(`Loading preset sample '${presetId}'...`);

    try {
      await new Promise(r => setTimeout(r, 200));
      setAnalysisStage('Extracting manifest components and DEX strings...');

      const response = await fetch(apiUrl(`/api/analyze/sample/${presetId}`), {
        method: 'POST',
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({ detail: 'Preset analysis failed' }));
        throw new Error(errData.detail || `Server returned ${response.status}`);
      }

      const data: RiskReport = await response.json();
      setReport(data);
      setActiveTab('overview');
    } catch (err: any) {
      setError(err.message || 'Failed to analyze sample preset');
    } finally {
      setIsAnalyzing(false);
      setAnalysisStage('');
    }
  };

  const runManualPermissionsAnalysis = async () => {
    setIsAnalyzing(true);
    setError(null);
    setAnalysisStage('Evaluating permissions against SpyAware risk rules...');

    const perms = manualPermsInput
      .split('\n')
      .map(p => p.trim())
      .filter(p => p.length > 0);

    try {
      const response = await fetch(apiUrl('/api/analyze/permissions'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          permissions: perms,
          target_name: 'Manual Permission Sandbox Input'
        }),
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({ detail: 'Analysis failed' }));
        throw new Error(errData.detail || `Server returned ${response.status}`);
      }

      const data: RiskReport = await response.json();
      setReport(data);
      setShowPermSandbox(false);
      setActiveTab('permissions');
    } catch (err: any) {
      setError(err.message || 'Failed to evaluate permissions');
    } finally {
      setIsAnalyzing(false);
      setAnalysisStage('');
    }
  };

  const getSeverityBadgeClass = (severity: Severity | string) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-rose-100 text-rose-800 border-rose-300';
      case 'HIGH':
        return 'bg-red-50 text-red-700 border-red-200';
      case 'MEDIUM':
        return 'bg-amber-50 text-amber-700 border-amber-200';
      case 'LOW':
        return 'bg-emerald-50 text-emerald-700 border-emerald-200';
      case 'INFO':
      default:
        return 'bg-blue-50 text-blue-700 border-blue-200';
    }
  };

  const getRiskLevelBadge = (level: string) => {
    switch (level) {
      case 'CRITICAL':
        return {
          bg: 'bg-rose-600 text-white',
          border: 'border-rose-500',
          icon: <ShieldAlert className="w-5 h-5 text-white" />
        };
      case 'HIGH':
        return {
          bg: 'bg-red-600 text-white',
          border: 'border-red-500',
          icon: <AlertTriangle className="w-5 h-5 text-white" />
        };
      case 'MEDIUM':
        return {
          bg: 'bg-amber-500 text-white',
          border: 'border-amber-400',
          icon: <AlertCircle className="w-5 h-5 text-white" />
        };
      case 'LOW':
        return {
          bg: 'bg-emerald-600 text-white',
          border: 'border-emerald-500',
          icon: <ShieldCheck className="w-5 h-5 text-white" />
        };
      case 'UNKNOWN':
      default:
        return {
          bg: 'bg-slate-600 text-white',
          border: 'border-slate-500',
          icon: <HelpCircle className="w-5 h-5 text-white" />
        };
    }
  };

  const getRuntimeStatusBadge = (status: string) => {
    switch (status) {
      case 'OBSERVED':
        return {
          badgeClass: 'bg-rose-100 text-rose-800 border-rose-300 font-bold',
          label: 'OBSERVED',
          icon: <ShieldAlert className="w-3.5 h-3.5 text-rose-600 shrink-0" />
        };
      case 'NOT_OBSERVED':
        return {
          badgeClass: 'bg-slate-100 text-slate-600 border-slate-200 font-medium',
          label: 'NOT OBSERVED',
          icon: <ShieldCheck className="w-3.5 h-3.5 text-slate-400 shrink-0" />
        };
      case 'UNAVAILABLE':
      case 'NOT_AVAILABLE':
        return {
          badgeClass: 'bg-amber-50 text-amber-800 border-amber-300 font-medium',
          label: 'UNAVAILABLE',
          icon: <AlertCircle className="w-3.5 h-3.5 text-amber-600 shrink-0" />
        };
      case 'NOT_TESTED':
        return {
          badgeClass: 'bg-blue-50 text-blue-700 border-blue-200 font-medium',
          label: 'NOT TESTED',
          icon: <Clock className="w-3.5 h-3.5 text-blue-500 shrink-0" />
        };
      case 'ERROR':
      default:
        return {
          badgeClass: 'bg-rose-50 text-rose-700 border-rose-200 font-medium',
          label: status,
          icon: <AlertTriangle className="w-3.5 h-3.5 text-rose-600 shrink-0" />
        };
    }
  };

  // Filter findings for findings tab
  const filteredFindings = report?.findings.filter(f => {
    const matchesSeverity = findingSeverityFilter === 'ALL' || f.severity === findingSeverityFilter;
    const matchesSearch =
      searchQuery === '' ||
      f.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.evidence.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesSeverity && matchesSearch;
  }) || [];

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 flex flex-col antialiased">
      {/* Top Header */}
      <header className="bg-white border-b border-slate-200 sticky top-0 z-30 shadow-xs">
        <div className="max-w-7xl mx-auto px-3 sm:px-6 lg:px-8 py-2.5 sm:py-0 sm:h-16 flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 sm:gap-4">
          <div className="flex items-center space-x-2.5 sm:space-x-3 min-w-0">
            <div className="w-8 h-8 sm:w-10 sm:h-10 rounded-lg bg-blue-600 flex items-center justify-center text-white shadow-xs shrink-0">
              <Shield className="w-5 h-5 sm:w-6 sm:h-6" />
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex items-center space-x-1.5 sm:space-x-2 flex-wrap">
                <span className="font-bold text-sm sm:text-lg tracking-tight text-slate-900 truncate">SPYAWARE ANALYZER</span>
                <span className="text-[10px] sm:text-xs px-1.5 sm:px-2 py-0.5 rounded-full bg-blue-50 text-blue-700 border border-blue-200 font-medium shrink-0">
                  Stage 2A Dynamic
                </span>
              </div>
              <p className="text-[11px] sm:text-xs text-slate-500 truncate hidden xs:block">Android Covert Surveillance Analysis Platform</p>
            </div>
          </div>

          <div className="flex items-center justify-between sm:justify-end space-x-2 sm:space-x-4 shrink-0 w-full sm:w-auto">
            <button
              onClick={() => setShowPermSandbox(true)}
              className="text-xs flex items-center space-x-1.5 px-3 py-2 sm:py-1.5 rounded-md bg-slate-100 hover:bg-slate-200 text-slate-700 font-medium transition-colors border border-slate-200 min-h-[38px] touch-manipulation"
            >
              <Sliders className="w-3.5 h-3.5 text-slate-500 shrink-0" />
              <span>Permission Sandbox</span>
            </button>
            <div className="flex items-center space-x-1.5 sm:space-x-2 text-xs text-slate-600 bg-slate-100 px-3 py-2 sm:py-1.5 rounded-md border border-slate-200 min-h-[38px]">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse shrink-0"></span>
              <span className="font-medium whitespace-nowrap">REST API Online</span>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="max-w-7xl mx-auto px-3 sm:px-6 lg:px-8 py-4 sm:py-8 flex-1 w-full space-y-6 sm:space-y-8 min-w-0 overflow-x-hidden">
        
        {/* Engine Status Cards Bar */}
        <section>
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-500">
              Analysis Engines & Subsystems
            </h2>
            <span className="text-xs text-slate-400">Core architecture modular status</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
            {/* Analysis Engine */}
            <div className="bg-white p-3.5 rounded-xl border border-slate-200 shadow-xs hover:border-blue-300 transition-colors flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-semibold text-slate-700 flex items-center space-x-1.5">
                    <FileCode className="w-4 h-4 text-blue-600" />
                    <span>Analysis Engine</span>
                  </span>
                  <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200">
                    AVAILABLE
                  </span>
                </div>
                <p className="text-[11px] text-slate-500 leading-snug">
                  Analyze installed Android applications for potential security risks.
                </p>
              </div>
              <button
                type="button"
                onClick={handleOpenAnalyzer}
                className="mt-3 w-full py-1.5 px-2.5 rounded-lg bg-blue-50 hover:bg-blue-100 text-blue-700 text-[11px] font-bold transition-colors flex items-center justify-center space-x-1 border border-blue-200/60 cursor-pointer"
              >
                <span>OPEN ANALYZER</span>
              </button>
            </div>

            {/* Permission */}
            <div className="bg-white p-3.5 rounded-xl border border-slate-200 shadow-xs hover:border-blue-300 transition-colors flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-semibold text-slate-700 flex items-center space-x-1.5">
                    <Lock className="w-4 h-4 text-blue-600" />
                    <span>Permissions</span>
                  </span>
                  <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200">
                    AVAILABLE
                  </span>
                </div>
                <p className="text-[11px] text-slate-500 leading-snug">
                  Weighted risk indicators and synergistic surveillance pattern combinations.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setShowPermSandbox(true)}
                className="mt-3 w-full py-1.5 px-2.5 rounded-lg bg-slate-50 hover:bg-slate-100 text-slate-700 text-[11px] font-medium transition-colors flex items-center justify-center space-x-1 border border-slate-200 cursor-pointer"
              >
                <span>TEST ENGINE</span>
              </button>
            </div>

            {/* Dynamic Stage 2B */}
            <div className="bg-white p-3.5 rounded-xl border border-slate-200 shadow-xs hover:border-blue-300 transition-colors flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-semibold text-slate-700 flex items-center space-x-1.5">
                    <Activity className="w-4 h-4 text-blue-600" />
                    <span>Dynamic Sandbox</span>
                  </span>
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                    envStatus?.ready
                      ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                      : 'bg-slate-100 text-slate-600 border-slate-200'
                  }`}>
                    {envStatus?.ready ? 'STAGE 2B READY' : 'STANDBY'}
                  </span>
                </div>
                <p className="text-[11px] text-slate-500 leading-snug">
                  {envStatus?.ready
                    ? `AVD '${envStatus.selected_avd}' ready for Stage 2B runtime behavioral observation.`
                    : 'Stage 2B: Isolated emulator runtime observation & dumpsys telemetry.'}
                </p>
              </div>
            </div>

            {/* Subsystem — Network Security */}
            <div className="bg-white p-3.5 rounded-xl border border-slate-200 shadow-xs hover:border-blue-300 transition-colors flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-semibold text-slate-700 flex items-center space-x-1.5">
                    <Network className="w-4 h-4 text-blue-600" />
                    <span>Network Security Analyzer</span>
                  </span>
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                    isMod4Installed
                      ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                      : 'bg-amber-50 text-amber-700 border-amber-200'
                  }`}>
                    {isMod4Installed ? 'Installed' : 'Not Installed'}
                  </span>
                </div>
                <p className="text-[11px] text-slate-500 leading-snug">
                  Network monitoring and security analysis.
                </p>
              </div>
              <button
                type="button"
                onClick={() => handleLaunchModule('com.spyaware.network')}
                className="mt-3 w-full py-1.5 px-2.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-[11px] font-bold transition-colors flex items-center justify-center space-x-1 shadow-xs cursor-pointer"
              >
                <span>OPEN MODULE</span>
              </button>
            </div>

            {/* Subsystem — BLE Surveillance Detection */}
            <div className="bg-white p-3.5 rounded-xl border border-slate-200 shadow-xs hover:border-blue-300 transition-colors flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-semibold text-slate-700 flex items-center space-x-1.5">
                    <Radio className="w-4 h-4 text-blue-600" />
                    <span>BLE Surveillance Detector</span>
                  </span>
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                    isMod5Installed
                      ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                      : 'bg-amber-50 text-amber-700 border-amber-200'
                  }`}>
                    {isMod5Installed ? 'Installed' : 'Not Installed'}
                  </span>
                </div>
                <p className="text-[11px] text-slate-500 leading-snug">
                  Detect nearby Bluetooth Low Energy devices and investigate suspicious device behavior.
                </p>
              </div>
              <button
                type="button"
                onClick={() => handleLaunchModule('com.example.spyaware')}
                className="mt-3 w-full py-1.5 px-2.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-[11px] font-bold transition-colors flex items-center justify-center space-x-1 shadow-xs cursor-pointer"
              >
                <span>OPEN MODULE</span>
              </button>
            </div>
          </div>
        </section>

        {/* Upload & Quick Demo Panel */}
        <section id="analyzer-upload-panel" className="bg-white rounded-2xl border border-slate-200 shadow-xs overflow-hidden">
          <div className="p-4 sm:p-6 md:p-8">
            <div className="max-w-3xl mx-auto text-center space-y-1.5 sm:space-y-2 mb-4 sm:mb-6">
              <h1 className="text-xl sm:text-2xl font-bold text-slate-900 tracking-tight leading-snug">
                Analyze Android APK for Covert Surveillance Indicators
              </h1>
              <p className="text-xs sm:text-sm text-slate-600">
                Upload an APK to inspect permissions, manifest components, DEX bytecode surveillance hooks, and runtime emulator telemetry.
              </p>
            </div>

            {/* Action Mode Selector: Choose APK vs Select Installed App */}
            <div className="max-w-md mx-auto mb-6 p-1 bg-slate-100 rounded-xl flex gap-1 border border-slate-200">
              <button
                type="button"
                onClick={() => { setUploadMode('file'); setError(null); }}
                className={`flex-1 py-2.5 px-3 rounded-lg text-xs sm:text-sm font-semibold flex items-center justify-center space-x-2 transition-all min-h-[42px] touch-manipulation ${
                  uploadMode === 'file'
                    ? 'bg-white text-blue-600 shadow-xs'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                <UploadCloud className="w-4 h-4 shrink-0" />
                <span className="truncate">Choose APK</span>
              </button>
              <button
                type="button"
                onClick={() => {
                  setUploadMode('installed');
                  setError(null);
                  if (installedApps.length === 0) {
                    loadInstalledApps(includeSystemApps);
                  }
                }}
                className={`flex-1 py-2.5 px-3 rounded-lg text-xs sm:text-sm font-semibold flex items-center justify-center space-x-2 transition-all min-h-[42px] touch-manipulation ${
                  uploadMode === 'installed'
                    ? 'bg-white text-blue-600 shadow-xs'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                <Smartphone className="w-4 h-4 shrink-0" />
                <span className="truncate">Select Installed App</span>
              </button>
            </div>

            {/* Method A: Choose APK Upload View */}
            {uploadMode === 'file' && (
              <div
                onDragOver={(e) => e.preventDefault()}
                onDrop={handleDrop}
                className={`border-2 border-dashed rounded-xl p-4 sm:p-6 md:p-8 text-center transition-all ${
                  selectedFile
                    ? 'border-blue-500 bg-blue-50/30'
                    : 'border-slate-300 hover:border-blue-400 bg-slate-50/50'
                }`}
              >
                <div className="flex flex-col items-center justify-center space-y-3">
                  <div className="w-10 h-10 sm:w-12 sm:h-12 rounded-full bg-blue-100 flex items-center justify-center text-blue-600 shrink-0">
                    <UploadCloud className="w-5 h-5 sm:w-6 sm:h-6" />
                  </div>

                  {selectedFile ? (
                    <div className="space-y-1 min-w-0 max-w-full">
                      <p className="text-sm font-semibold text-slate-900 break-all">{selectedFile.name}</p>
                      <p className="text-xs text-slate-500">
                        {formatBytes(selectedFile.size)} • Ready for analysis
                      </p>
                    </div>
                  ) : (
                    <div className="space-y-2">
                      <p className="text-xs sm:text-sm font-medium text-slate-700">
                        Select an APK from your device storage or drag and drop here
                      </p>
                      <div>
                        <label className="inline-flex items-center space-x-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-xs font-semibold cursor-pointer shadow-xs transition-colors min-h-[40px] touch-manipulation">
                          <UploadCloud className="w-4 h-4" />
                          <span>Choose APK File</span>
                          <input
                            type="file"
                            accept=".apk,.zip,application/vnd.android.package-archive"
                            className="hidden"
                            onChange={handleFileChange}
                            disabled={isAnalyzing}
                          />
                        </label>
                      </div>
                      <p className="text-[11px] sm:text-xs text-slate-400">Accepts .apk packages up to 100 MB</p>
                    </div>
                  )}

                  {/* Dynamic & Network Analysis Options Toggle */}
                  <div className="pt-2 flex flex-col sm:flex-row items-stretch sm:items-center gap-2 w-full sm:w-auto">
                    <label className="flex items-center justify-between sm:justify-start space-x-2 text-xs text-slate-700 cursor-pointer bg-white px-3 py-2 rounded-lg border border-slate-200 shadow-2xs hover:border-blue-300 min-h-[40px]">
                      <div className="flex items-center space-x-2 min-w-0">
                        <input
                          type="checkbox"
                          checked={runDynamic}
                          onChange={(e) => setRunDynamic(e.target.checked)}
                          className="rounded text-blue-600 focus:ring-blue-500 h-4 w-4 shrink-0"
                        />
                        <span className="font-medium truncate">Execute Dynamic Sandbox (Stage 2B)</span>
                      </div>
                      <span className="text-[10px] text-slate-400 font-mono shrink-0 pl-1">
                        {envStatus?.selected_avd ? `[${envStatus.selected_avd}]` : '[Auto]'}
                      </span>
                    </label>

                    <label className="flex items-center justify-between sm:justify-start space-x-2 text-xs text-slate-700 cursor-pointer bg-white px-3 py-2 rounded-lg border border-slate-200 shadow-2xs hover:border-blue-300 min-h-[40px]">
                      <div className="flex items-center space-x-2 min-w-0">
                        <input
                          type="checkbox"
                          checked={runNetwork}
                          onChange={(e) => setRunNetwork(e.target.checked)}
                          className="rounded text-blue-600 focus:ring-blue-500 h-4 w-4 shrink-0"
                        />
                        <span className="font-medium truncate">Audit Network Sockets (Stage 2C)</span>
                      </div>
                      <span className="text-[10px] text-blue-600 font-bold bg-blue-50 px-1.5 py-0.5 rounded border border-blue-200 shrink-0">
                        UID Sockets
                      </span>
                    </label>
                  </div>

                  {/* Action Buttons */}
                  <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2.5 sm:gap-3 pt-2 w-full sm:w-auto">
                    <button
                      onClick={() => selectedFile && runAnalysis(selectedFile)}
                      disabled={!selectedFile || isAnalyzing}
                      className={`w-full sm:w-auto px-5 py-2.5 rounded-lg text-sm font-semibold flex items-center justify-center space-x-2 transition-all shadow-xs min-h-[44px] touch-manipulation ${
                        !selectedFile || isAnalyzing
                          ? 'bg-slate-200 text-slate-400 cursor-not-allowed'
                          : 'bg-blue-600 hover:bg-blue-700 text-white shadow-blue-500/20 hover:shadow-blue-500/30'
                      }`}
                    >
                      {isAnalyzing ? (
                        <>
                          <RefreshCw className="w-4 h-4 animate-spin" />
                          <span>Analyzing...</span>
                        </>
                      ) : (
                        <>
                          <Shield className="w-4 h-4" />
                          <span>Analyze APK</span>
                        </>
                      )}
                    </button>

                    {selectedFile && !isAnalyzing && (
                      <button
                        onClick={() => setSelectedFile(null)}
                        className="w-full sm:w-auto px-3.5 py-2.5 rounded-lg text-sm text-slate-600 hover:text-slate-900 hover:bg-slate-100 transition-colors font-medium min-h-[44px] touch-manipulation text-center"
                      >
                        Clear
                      </button>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* Method B: Select Installed App View */}
            {uploadMode === 'installed' && (
              <div className="space-y-4">
                {!isBridgeAvailable && connectedDevices.length === 0 && installedApps.length === 0 && !isLoadingApps ? (
                  <div className="border border-slate-200 rounded-xl p-6 sm:p-8 text-center bg-slate-50/50 space-y-4 max-w-xl mx-auto">
                    <div className="w-12 h-12 rounded-full bg-slate-100 flex items-center justify-center text-slate-500 mx-auto">
                      <Smartphone className="w-6 h-6" />
                    </div>
                    <div className="space-y-1.5">
                      <h3 className="text-sm font-bold text-slate-900">Desktop ADB Device Discovery</h3>
                      <p className="text-xs text-slate-600 leading-relaxed">
                        To discover and analyze installed applications in desktop mode, ensure an Android emulator or device is running with USB debugging enabled.
                      </p>
                    </div>
                    <div className="flex items-center justify-center space-x-3">
                      <button
                        type="button"
                        onClick={() => loadInstalledApps(includeSystemApps)}
                        className="px-4 py-2 bg-blue-600 text-white rounded-lg text-xs font-semibold hover:bg-blue-700 transition-colors inline-flex items-center space-x-1.5 shadow-xs"
                      >
                        <RefreshCw className="w-3.5 h-3.5" />
                        <span>Detect Connected Devices</span>
                      </button>
                      <button
                        type="button"
                        onClick={() => setUploadMode('file')}
                        className="px-4 py-2 bg-white text-slate-700 border border-slate-300 rounded-lg text-xs font-semibold hover:bg-slate-50 transition-colors inline-flex items-center space-x-1.5 shadow-2xs"
                      >
                        <UploadCloud className="w-3.5 h-3.5" />
                        <span>Switch to Choose APK</span>
                      </button>
                    </div>
                  </div>
                ) : selectedApp ? (
                  /* Selected App Confirmation View */
                  <div className="border border-blue-200 bg-blue-50/20 rounded-xl p-4 sm:p-6 space-y-4 max-w-2xl mx-auto">
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex items-center space-x-3 min-w-0">
                        {selectedApp.icon ? (
                          <img
                            src={selectedApp.icon}
                            alt=""
                            className="w-12 h-12 sm:w-14 sm:h-14 rounded-xl object-contain bg-white p-1 border border-slate-200 shadow-2xs shrink-0"
                          />
                        ) : (
                          <div className="w-12 h-12 sm:w-14 sm:h-14 rounded-xl bg-blue-100 text-blue-600 flex items-center justify-center shrink-0">
                            <Smartphone className="w-6 h-6 sm:w-7 sm:h-7" />
                          </div>
                        )}
                        <div className="min-w-0">
                          <h3 className="text-sm sm:text-base font-bold text-slate-900 truncate">
                            {selectedApp.appName}
                          </h3>
                          <p className="text-xs font-mono text-slate-500 truncate">
                            {selectedApp.packageName}
                          </p>
                          <div className="flex items-center space-x-2 mt-1 flex-wrap gap-y-1">
                            <span className="text-[10px] text-slate-600 bg-white px-2 py-0.5 rounded border border-slate-200">
                              v{selectedApp.versionName}
                            </span>
                            <span className="text-[10px] text-slate-600 bg-white px-2 py-0.5 rounded border border-slate-200">
                              {formatBytes(selectedApp.apkSize)}
                            </span>
                            <span className={`text-[10px] font-medium px-2 py-0.5 rounded border ${
                              selectedApp.isSystem
                                ? 'bg-amber-50 text-amber-700 border-amber-200'
                                : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                            }`}>
                              {selectedApp.isSystem ? 'System App' : 'User App'}
                            </span>
                          </div>
                        </div>
                      </div>

                      <button
                        type="button"
                        onClick={() => setSelectedApp(null)}
                        disabled={isAnalyzing}
                        className="text-xs text-slate-500 hover:text-slate-800 underline underline-offset-2 shrink-0 py-1"
                      >
                        Change
                      </button>
                    </div>

                    {/* Split APK Limitation Warning */}
                    {selectedApp.isSplit && (
                      <div className="p-3 bg-amber-50 rounded-lg border border-amber-200 flex items-start space-x-2 text-xs text-amber-800">
                        <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
                        <div>
                          <span className="font-semibold">Split APK Installation Detected: </span>
                          This app is installed with base.apk plus {selectedApp.splitCount} configuration splits.
                          Analysis will inspect the core base.apk (manifest & main bytecode). Configuration splits (resources/assets) will not be included.
                        </div>
                      </div>
                    )}

                    {/* Sandbox options */}
                    <div className="pt-2 flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
                      <label className="flex items-center justify-between sm:justify-start space-x-2 text-xs text-slate-700 cursor-pointer bg-white px-3 py-2 rounded-lg border border-slate-200 shadow-2xs hover:border-blue-300 min-h-[40px] flex-1">
                        <div className="flex items-center space-x-2 min-w-0">
                          <input
                            type="checkbox"
                            checked={runDynamic}
                            onChange={(e) => setRunDynamic(e.target.checked)}
                            className="rounded text-blue-600 focus:ring-blue-500 h-4 w-4 shrink-0"
                          />
                          <span className="font-medium truncate">Execute Dynamic Sandbox (Stage 2B)</span>
                        </div>
                      </label>

                      <label className="flex items-center justify-between sm:justify-start space-x-2 text-xs text-slate-700 cursor-pointer bg-white px-3 py-2 rounded-lg border border-slate-200 shadow-2xs hover:border-blue-300 min-h-[40px] flex-1">
                        <div className="flex items-center space-x-2 min-w-0">
                          <input
                            type="checkbox"
                            checked={runNetwork}
                            onChange={(e) => setRunNetwork(e.target.checked)}
                            className="rounded text-blue-600 focus:ring-blue-500 h-4 w-4 shrink-0"
                          />
                          <span className="font-medium truncate">Audit Network Sockets (Stage 2C)</span>
                        </div>
                      </label>
                    </div>

                    {/* Action buttons */}
                    <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2.5 pt-2">
                      <button
                        onClick={() => startInstalledAppAnalysis(selectedApp)}
                        disabled={isAnalyzing}
                        className={`px-5 py-2.5 rounded-lg text-sm font-semibold flex items-center justify-center space-x-2 transition-all shadow-xs min-h-[44px] touch-manipulation flex-1 ${
                          isAnalyzing
                            ? 'bg-slate-200 text-slate-400 cursor-not-allowed'
                            : 'bg-blue-600 hover:bg-blue-700 text-white shadow-blue-500/20 hover:shadow-blue-500/30'
                        }`}
                      >
                        {isAnalyzing ? (
                          <>
                            <RefreshCw className="w-4 h-4 animate-spin" />
                            <span>Analyzing...</span>
                          </>
                        ) : (
                          <>
                            <Shield className="w-4 h-4" />
                            <span>Analyze {selectedApp.appName}</span>
                          </>
                        )}
                      </button>

                      {isAnalyzing ? (
                        <button
                          onClick={cancelInstalledAnalysis}
                          className="px-4 py-2.5 rounded-lg text-xs font-semibold text-rose-600 hover:bg-rose-50 border border-rose-200 min-h-[44px]"
                        >
                          Cancel
                        </button>
                      ) : (
                        <button
                          onClick={() => setSelectedApp(null)}
                          className="px-4 py-2.5 rounded-lg text-xs font-medium text-slate-600 hover:bg-slate-100 border border-slate-200 min-h-[44px]"
                        >
                          Select Different App
                        </button>
                      )}
                    </div>
                  </div>
                ) : (
                  /* Installed App List View */
                  <div className="space-y-3">
                    {/* Controls Toolbar */}
                    <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-2.5">
                      {/* Search Bar */}
                      <div className="relative flex-1 min-w-0">
                        <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
                        <input
                          type="text"
                          value={appSearchQuery}
                          onChange={(e) => setAppSearchQuery(e.target.value)}
                          placeholder="Search by app name or package..."
                          className="w-full pl-9 pr-8 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:bg-white transition-all"
                        />
                        {appSearchQuery && (
                          <button
                            onClick={() => setAppSearchQuery('')}
                            className="absolute right-2.5 top-2.5 text-slate-400 hover:text-slate-600"
                          >
                            <XCircle className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </div>

                      {/* System Apps Toggle & Refresh */}
                      <div className="flex items-center justify-between sm:justify-end space-x-2 shrink-0">
                        <label className="flex items-center space-x-1.5 text-xs text-slate-600 cursor-pointer bg-slate-50 px-2.5 py-2 rounded-lg border border-slate-200 hover:border-slate-300">
                          <input
                            type="checkbox"
                            checked={includeSystemApps}
                            onChange={(e) => {
                              const next = e.target.checked;
                              setIncludeSystemApps(next);
                              loadInstalledApps(next);
                            }}
                            className="rounded text-blue-600 focus:ring-blue-500 h-3.5 w-3.5"
                          />
                          <span className="font-medium whitespace-nowrap">System Apps</span>
                        </label>

                        <button
                          onClick={() => loadInstalledApps(includeSystemApps)}
                          disabled={isLoadingApps}
                          className="px-2.5 py-2 rounded-lg text-xs font-medium bg-slate-50 hover:bg-slate-100 text-slate-700 border border-slate-200 flex items-center space-x-1 transition-colors"
                          title="Refresh installed apps from device"
                        >
                          <RefreshCw className={`w-3.5 h-3.5 ${isLoadingApps ? 'animate-spin text-blue-600' : 'text-slate-500'}`} />
                          <span className="hidden xs:inline">Refresh</span>
                        </button>
                      </div>
                    </div>

                    {/* App Count summary */}
                    <div className="flex items-center justify-between text-[11px] text-slate-500 px-1">
                      <span>
                        Showing {installedApps.filter(a => {
                          if (!appSearchQuery.trim()) return true;
                          const q = appSearchQuery.toLowerCase();
                          return a.appName.toLowerCase().includes(q) || a.packageName.toLowerCase().includes(q);
                        }).length} {includeSystemApps ? 'applications' : 'user applications'}
                      </span>
                      <span>Select an app to analyze its installed APK</span>
                    </div>

                    {/* App List Container */}
                    {isLoadingApps ? (
                      <div className="p-8 text-center bg-slate-50/50 rounded-xl border border-slate-200 space-y-2">
                        <RefreshCw className="w-6 h-6 animate-spin text-blue-600 mx-auto" />
                        <p className="text-xs font-medium text-slate-600">Enumerating installed applications from Android device...</p>
                      </div>
                    ) : (
                      <div className="max-h-[360px] overflow-y-auto space-y-2 pr-1 rounded-xl">
                        {installedApps
                          .filter(a => {
                            if (!appSearchQuery.trim()) return true;
                            const q = appSearchQuery.toLowerCase();
                            return a.appName.toLowerCase().includes(q) || a.packageName.toLowerCase().includes(q);
                          })
                          .map((app) => (
                            <div
                              key={app.packageName}
                              onClick={() => setSelectedApp(app)}
                              className="p-3 rounded-xl border border-slate-200 hover:border-blue-400 bg-white hover:bg-blue-50/10 cursor-pointer transition-all flex items-center justify-between gap-3 shadow-2xs group"
                            >
                              <div className="flex items-center space-x-3 min-w-0">
                                {app.icon ? (
                                  <img
                                    src={app.icon}
                                    alt=""
                                    className="w-9 h-9 sm:w-10 sm:h-10 rounded-lg object-contain bg-slate-50 p-0.5 border border-slate-100 shrink-0"
                                  />
                                ) : (
                                  <div className="w-9 h-9 sm:w-10 sm:h-10 rounded-lg bg-blue-50 text-blue-600 flex items-center justify-center shrink-0">
                                    <Smartphone className="w-5 h-5" />
                                  </div>
                                )}
                                <div className="min-w-0 flex-1">
                                  <div className="flex items-center space-x-1.5 flex-wrap gap-y-0.5">
                                    <h4 className="text-xs font-bold text-slate-900 group-hover:text-blue-600 transition-colors truncate">
                                      {app.appName}
                                    </h4>
                                    {app.isSystem ? (
                                      <span className="text-[9px] px-1.5 py-0.2 rounded bg-amber-50 text-amber-700 border border-amber-200">
                                        System
                                      </span>
                                    ) : (
                                      <span className="text-[9px] px-1.5 py-0.2 rounded bg-emerald-50 text-emerald-700 border border-emerald-200">
                                        User
                                      </span>
                                    )}
                                    {app.isSplit && (
                                      <span className="text-[9px] px-1.5 py-0.2 rounded bg-blue-50 text-blue-700 border border-blue-200">
                                        Split
                                      </span>
                                    )}
                                  </div>
                                  <p className="text-[11px] font-mono text-slate-500 truncate">
                                    {app.packageName}
                                  </p>
                                </div>
                              </div>

                              <div className="flex items-center space-x-2 shrink-0">
                                <span className="text-[10px] text-slate-400 hidden sm:inline">
                                  {formatBytes(app.apkSize)}
                                </span>
                                <button
                                  type="button"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setSelectedApp(app);
                                  }}
                                  className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-blue-50 group-hover:bg-blue-600 text-blue-700 group-hover:text-white border border-blue-200 group-hover:border-blue-600 transition-all"
                                >
                                  Select
                                </button>
                              </div>
                            </div>
                          ))}

                        {installedApps.filter(a => {
                          if (!appSearchQuery.trim()) return true;
                          const q = appSearchQuery.toLowerCase();
                          return a.appName.toLowerCase().includes(q) || a.packageName.toLowerCase().includes(q);
                        }).length === 0 && (
                          <div className="p-8 text-center bg-slate-50/50 rounded-xl border border-slate-200 space-y-2">
                            <Smartphone className="w-8 h-8 text-slate-400 mx-auto" />
                            <p className="text-xs font-semibold text-slate-700">No applications found</p>
                            <p className="text-[11px] text-slate-400">
                              {appSearchQuery
                                ? `No application matched "${appSearchQuery}". Try a different keyword.`
                                : 'No applications enumerated. Click Refresh to query again.'}
                            </p>
                            {appSearchQuery && (
                              <button
                                onClick={() => setAppSearchQuery('')}
                                className="text-xs text-blue-600 hover:underline font-medium"
                              >
                                Clear search
                              </button>
                            )}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* Analysis Progress Bar */}
            {isAnalyzing && (
              <div className="mt-4 sm:mt-6 p-4 rounded-xl bg-blue-50/70 border border-blue-200">
                <div className="flex items-center justify-between text-xs font-medium text-blue-900 mb-2">
                  <span className="flex items-center space-x-2">
                    <RefreshCw className="w-3.5 h-3.5 animate-spin text-blue-600 shrink-0" />
                    <span className="truncate">{analysisStage}</span>
                  </span>
                  <span className="shrink-0 pl-2 font-mono font-bold">
                    {uploadPercent > 0 ? `${uploadPercent}%` : 'Scanning...'}
                  </span>
                </div>
                <div className="w-full bg-blue-200/60 rounded-full h-1.5 overflow-hidden">
                  <div
                    className="bg-blue-600 h-1.5 rounded-full transition-all duration-300"
                    style={{ width: `${Math.max(8, uploadPercent || 75)}%` }}
                  ></div>
                </div>
              </div>
            )}

            {/* Error Message */}
            {error && (
              <div className="mt-4 sm:mt-6 p-4 rounded-xl bg-rose-50 border border-rose-200 flex items-start space-x-3">
                <AlertCircle className="w-5 h-5 text-rose-600 shrink-0 mt-0.5" />
                <div className="min-w-0 flex-1">
                  <h4 className="text-sm font-semibold text-rose-900">Analysis Error</h4>
                  <p className="text-xs text-rose-700 mt-0.5 break-words">{error}</p>
                </div>
                <button
                  type="button"
                  onClick={() => setError(null)}
                  className="text-rose-400 hover:text-rose-600 text-xs shrink-0 p-1"
                >
                  <XCircle className="w-4 h-4" />
                </button>
              </div>
            )}

            {/* Quick Demo Samples Bar */}
            <div className="mt-4 sm:mt-6 pt-4 sm:pt-6 border-t border-slate-100">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div>
                  <span className="text-xs font-semibold text-slate-700">Quick Test Samples:</span>
                  <p className="text-[11px] text-slate-400">Run pre-configured synthetic APK evaluations immediately</p>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:flex lg:flex-wrap items-center gap-2 w-full lg:w-auto">
                  {PRESET_SAMPLES.map(sample => (
                    <button
                      key={sample.id}
                      onClick={() => runPresetAnalysis(sample.id)}
                      disabled={isAnalyzing}
                      className="px-3 py-2 rounded-lg text-xs font-medium bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 hover:border-slate-300 shadow-2xs transition-all flex items-center justify-between gap-2 min-h-[44px] touch-manipulation min-w-0"
                    >
                      <span className="truncate">{sample.name}</span>
                      <span className={`text-[10px] px-1.5 py-0.5 rounded border font-semibold shrink-0 whitespace-nowrap ${sample.badgeColor}`}>
                        {sample.expected}
                      </span>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Results Section */}
        {report && (
          <section className="space-y-6">
            
            {/* Legal / Technical Disclaimer Banner */}
            <div className="p-3.5 rounded-xl bg-amber-50/80 border border-amber-200 flex items-center space-x-3 text-amber-900 text-xs">
              <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0" />
              <p>
                <span className="font-semibold">Notice:</span> {report.disclaimer}
              </p>
            </div>

            {/* Analysis Execution Status Banner */}
            {report.analysis_status === 'COMPLETED_CLEAN' && (
              <div className="p-4 rounded-xl bg-emerald-50 border border-emerald-200 flex items-start space-x-3 text-emerald-900 text-xs">
                <CheckCircle className="w-5 h-5 text-emerald-600 shrink-0 mt-0.5" />
                <div>
                  <h4 className="font-bold text-sm text-emerald-950">Analysis Completed — No Suspicious Indicators</h4>
                  <p className="mt-0.5 text-emerald-800">
                    The application passed static manifest, DEX bytecode, and permission audits with 0 confirmed surveillance indicators.
                  </p>
                </div>
              </div>
            )}
            {report.analysis_status === 'PARTIAL' && (
              <div className="p-4 rounded-xl bg-amber-50 border border-amber-200 flex items-start space-x-3 text-amber-900 text-xs">
                <AlertTriangle className="w-5 h-5 text-amber-600 shrink-0 mt-0.5" />
                <div>
                  <h4 className="font-bold text-sm text-amber-950">Partial Analysis — Incomplete Modules</h4>
                  <p className="mt-0.5 text-amber-800">
                    One or more requested analysis modules could not be completed. Partial results evaluate only completed modules and must not be interpreted as verification of application safety.
                  </p>
                </div>
              </div>
            )}
            {report.analysis_status === 'FAILED' && (
              <div className="p-4 rounded-xl bg-rose-50 border border-rose-200 flex items-start space-x-3 text-rose-900 text-xs">
                <XCircle className="w-5 h-5 text-rose-600 shrink-0 mt-0.5" />
                <div>
                  <h4 className="font-bold text-sm text-rose-950">Analysis Failed</h4>
                  <p className="mt-0.5 text-rose-800">
                    Analysis modules failed during execution. Please check module status and error details below.
                  </p>
                </div>
              </div>
            )}
            {report.analysis_status === 'INCONCLUSIVE' && (
              <div className="p-4 rounded-xl bg-slate-100 border border-slate-300 flex items-start space-x-3 text-slate-900 text-xs">
                <HelpCircle className="w-5 h-5 text-slate-600 shrink-0 mt-0.5" />
                <div>
                  <h4 className="font-bold text-sm text-slate-950">Analysis Inconclusive</h4>
                  <p className="mt-0.5 text-slate-700">
                    No active analysis modules completed successfully. Risk score could not be determined.
                  </p>
                </div>
              </div>
            )}

            {/* Limitations & Split APK Banner */}
            {(report.is_split || (report.limitations && report.limitations.length > 0)) && (
              <div className="p-4 rounded-xl bg-blue-50 border border-blue-200 space-y-2 text-xs text-blue-900">
                <div className="flex items-center space-x-2 font-bold text-blue-950">
                  <AlertCircle className="w-4 h-4 text-blue-600 shrink-0" />
                  <span>Analysis Limitations & Split APK Notice</span>
                </div>
                <ul className="list-disc list-inside space-y-1 text-blue-800">
                  {report.limitations?.map((lim, idx) => (
                    <li key={idx}>{lim}</li>
                  ))}
                  {report.is_split && !report.limitations?.some(l => l.includes('split')) && (
                    <li>Application is installed as a split APK package ({report.split_count} splits). Only base APK was analyzed.</li>
                  )}
                </ul>
              </div>
            )}

            {/* Top Score Cards Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3 sm:gap-4">
              
              {/* Overall Risk Score */}
              <div className="col-span-1 sm:col-span-2 lg:col-span-1 bg-white p-4 sm:p-5 rounded-2xl border border-slate-200 shadow-xs space-y-2.5 sm:space-y-3 min-w-0">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-semibold uppercase tracking-wider text-slate-500 truncate">
                    Overall Risk Score
                  </span>
                  <div className={`px-2 py-0.5 rounded-md text-[11px] font-bold flex items-center space-x-1 shrink-0 ${getRiskLevelBadge(report.risk_level).bg}`}>
                    {getRiskLevelBadge(report.risk_level).icon}
                    <span>{report.risk_level}</span>
                  </div>
                </div>

                <div className="flex items-baseline space-x-2">
                  <span className="text-3xl sm:text-4xl font-extrabold text-slate-900">
                    {report.risk_level === 'UNKNOWN' ? '—' : report.overall_score.toFixed(1)}
                  </span>
                  <span className="text-xs text-slate-400">
                    {report.risk_level === 'UNKNOWN' ? '(Inconclusive)' : '/ 100'}
                  </span>
                </div>

                {/* Progress track */}
                <div className="w-full bg-slate-100 rounded-full h-2 overflow-hidden">
                  <div
                    className={`h-2 rounded-full transition-all duration-500 ${
                      report.risk_level === 'UNKNOWN'
                        ? 'bg-slate-300'
                        : report.overall_score >= 75
                        ? 'bg-rose-600'
                        : report.overall_score >= 50
                        ? 'bg-red-500'
                        : report.overall_score >= 25
                        ? 'bg-amber-500'
                        : 'bg-emerald-500'
                    }`}
                    style={{ width: `${report.risk_level === 'UNKNOWN' ? 0 : Math.min(100, report.overall_score)}%` }}
                  ></div>
                </div>
                {report.risk_level === 'UNKNOWN' ? (
                  <p className="text-[11px] text-amber-800 bg-amber-50 p-2 rounded-lg border border-amber-200 leading-snug">
                    <span className="font-semibold">Analysis Inconclusive:</span> The analysis could not determine a reliable risk score because no analysis module completed successfully.
                  </p>
                ) : (
                  <p className="text-[11px] text-slate-500">
                    Calculated using risk-weighted peak-and-mean aggregation.
                  </p>
                )}
              </div>

              {/* Static Score */}
              <div className="bg-white p-4 sm:p-5 rounded-2xl border border-slate-200 shadow-xs space-y-2.5 sm:space-y-3 min-w-0">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-semibold uppercase tracking-wider text-slate-500 truncate">
                    Static Score
                  </span>
                  <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200 shrink-0">
                    STAGE 1
                  </span>
                </div>
                <div className="flex items-baseline space-x-2">
                  <span className="text-3xl sm:text-4xl font-extrabold text-slate-900">
                    {report.module_scores.static !== null ? report.module_scores.static.toFixed(1) : 'N/A'}
                  </span>
                  <span className="text-xs text-slate-400">/ 100</span>
                </div>
                <div className="w-full bg-slate-100 rounded-full h-2 overflow-hidden">
                  <div
                    className="bg-blue-600 h-2 rounded-full"
                    style={{ width: `${Math.min(100, report.module_scores.static || 0)}%` }}
                  ></div>
                </div>
                <p className="text-[11px] text-slate-500">
                  DEX API calls, manifest components, and native binaries.
                </p>
              </div>

              {/* Permission Score */}
              <div className="bg-white p-4 sm:p-5 rounded-2xl border border-slate-200 shadow-xs space-y-2.5 sm:space-y-3 min-w-0">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-semibold uppercase tracking-wider text-slate-500 truncate">
                    Permission Score
                  </span>
                  <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200 shrink-0">
                    STAGE 1
                  </span>
                </div>
                <div className="flex items-baseline space-x-2">
                  <span className="text-3xl sm:text-4xl font-extrabold text-slate-900">
                    {report.module_scores.permissions !== null
                      ? report.module_scores.permissions.toFixed(1)
                      : 'N/A'}
                  </span>
                  <span className="text-xs text-slate-400">/ 100</span>
                </div>
                <div className="w-full bg-slate-100 rounded-full h-2 overflow-hidden">
                  <div
                    className="bg-indigo-600 h-2 rounded-full"
                    style={{ width: `${Math.min(100, report.module_scores.permissions || 0)}%` }}
                  ></div>
                </div>
                <p className="text-[11px] text-slate-500">
                  Individual sensitive permissions and synergy combinations.
                </p>
              </div>

              {/* Dynamic Sandbox Score */}
              <div className="bg-white p-4 sm:p-5 rounded-2xl border border-slate-200 shadow-xs space-y-2.5 sm:space-y-3 min-w-0">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-semibold uppercase tracking-wider text-slate-500 truncate">
                    Dynamic Score
                  </span>
                  <div className="flex items-center space-x-1.5 shrink-0">
                    <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-slate-100 text-slate-600">
                      STAGE 2B
                    </span>
                    {(() => {
                      const dynStatus = report.dynamic_details?.status || report.module_status?.dynamic;
                      if (!dynStatus || dynStatus === 'COMPLETED') return null;
                      const badge = getModuleStatusBadge(dynStatus);
                      return (
                        <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${badge.badgeClass}`}>
                          {badge.label}
                        </span>
                      );
                    })()}
                  </div>
                </div>
                <div className="flex items-baseline space-x-2">
                  <span className="text-3xl sm:text-4xl font-extrabold text-slate-900">
                    {report.module_scores.dynamic !== null
                      ? report.module_scores.dynamic.toFixed(1)
                      : 'N/A'}
                  </span>
                  <span className="text-xs text-slate-400">
                    {report.module_scores.dynamic !== null
                      ? '/ 100'
                      : report.dynamic_details?.status || 'Not Evaluated'}
                  </span>
                </div>
                <div className="w-full bg-slate-100 rounded-full h-2 overflow-hidden">
                  <div
                    className={`${report.module_scores.dynamic !== null ? 'bg-emerald-600' : 'bg-slate-200'} h-2 rounded-full`}
                    style={{ width: `${report.module_scores.dynamic !== null ? Math.min(100, report.module_scores.dynamic) : 0}%` }}
                  ></div>
                </div>
                <p className="text-[11px] text-slate-500 truncate" title={report.module_errors?.dynamic || report.dynamic_details?.error_message || undefined}>
                  {report.dynamic_details?.status && report.dynamic_details.status !== 'COMPLETED'
                    ? `Status: ${report.dynamic_details.status}${report.dynamic_details.error_message ? ` - ${report.dynamic_details.error_message}` : ''}`
                    : 'Runtime lifecycle, logcat APIs, and active service state.'}
                </p>
              </div>

              {/* Network Analysis Score */}
              <div className="bg-white p-4 sm:p-5 rounded-2xl border border-slate-200 shadow-xs space-y-2.5 sm:space-y-3 min-w-0">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-semibold uppercase tracking-wider text-slate-500 truncate">
                    Network Score
                  </span>
                  <div className="flex items-center space-x-1.5 shrink-0">
                    <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200">
                      STAGE 2C
                    </span>
                    {(() => {
                      const netStatus = report.network_details?.status || report.module_status?.network;
                      if (!netStatus || netStatus === 'COMPLETED' || netStatus === 'NOT_ATTRIBUTED') return null;
                      const badge = getModuleStatusBadge(netStatus);
                      return (
                        <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${badge.badgeClass}`}>
                          {badge.label}
                        </span>
                      );
                    })()}
                  </div>
                </div>
                <div className="flex items-baseline space-x-2">
                  <span className="text-3xl sm:text-4xl font-extrabold text-slate-900">
                    {report.module_scores.network !== null
                      ? report.module_scores.network.toFixed(1)
                      : 'N/A'}
                  </span>
                  <span className="text-xs text-slate-400">
                    {report.module_scores.network !== null
                      ? '/ 100'
                      : report.network_details?.status || 'Not Evaluated'}
                  </span>
                </div>
                <div className="w-full bg-slate-100 rounded-full h-2 overflow-hidden">
                  <div
                    className={`${report.module_scores.network !== null ? 'bg-purple-600' : 'bg-slate-200'} h-2 rounded-full`}
                    style={{ width: `${report.module_scores.network !== null ? Math.min(100, report.module_scores.network) : 0}%` }}
                  ></div>
                </div>
                <p className="text-[11px] text-slate-500 truncate" title={report.module_errors?.network || report.network_details?.error_message || undefined}>
                  {report.network_details?.status && report.network_details.status !== 'COMPLETED'
                    ? `Status: ${report.network_details.status}${report.network_details.error_message ? ` - ${report.network_details.error_message}` : ''}`
                    : 'Attributed socket events, surveillance destinations, and HTTP flows.'}
                </p>
              </div>
            </div>

            {/* Risk Assessment Summary Narrative */}
            <div className="bg-white p-4 sm:p-5 rounded-2xl border border-slate-200 shadow-xs space-y-2.5">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-500 flex items-center space-x-1.5">
                <FileText className="w-4 h-4 text-blue-600 shrink-0" />
                <span>Executive Risk Summary</span>
              </h3>
              <p className="text-xs sm:text-sm text-slate-800 leading-relaxed font-normal">
                {report.summary}
              </p>
              <div className="pt-2 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs text-slate-500 border-t border-slate-100">
                <div className="flex flex-col sm:flex-row sm:items-center gap-1.5 sm:gap-4">
                  <span className="break-all"><strong className="text-slate-700">Analysis ID:</strong> {report.analysis_id}</span>
                  <span className="break-all"><strong className="text-slate-700">Timestamp:</strong> {new Date(report.timestamp).toLocaleString()}</span>
                  <span className="break-all"><strong className="text-slate-700">Target File:</strong> {report.apk_filename}</span>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(report, null, 2));
                    const downloadAnchor = document.createElement('a');
                    downloadAnchor.setAttribute('href', dataStr);
                    downloadAnchor.setAttribute('download', `spyaware_report_${report.analysis_id || 'export'}.json`);
                    document.body.appendChild(downloadAnchor);
                    downloadAnchor.click();
                    downloadAnchor.remove();
                  }}
                  className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg border border-slate-300 bg-white text-xs font-semibold text-slate-700 hover:bg-slate-50 transition shadow-2xs self-start sm:self-auto cursor-pointer"
                >
                  <Download className="w-3.5 h-3.5 text-slate-500" />
                  <span>Export Report (JSON)</span>
                </button>
                <button
                  type="button"
                  onClick={async () => {
                    try {
                      const res = await fetch(apiUrl(`/api/analysis/${report.analysis_id}/export/markdown`));
                      if (res.ok) {
                        const mdText = await res.text();
                        const dataStr = 'data:text/markdown;charset=utf-8,' + encodeURIComponent(mdText);
                        const downloadAnchor = document.createElement('a');
                        downloadAnchor.setAttribute('href', dataStr);
                        downloadAnchor.setAttribute('download', `spyaware_report_${report.analysis_id || 'export'}.md`);
                        document.body.appendChild(downloadAnchor);
                        downloadAnchor.click();
                        downloadAnchor.remove();
                      }
                    } catch {
                      // ignore
                    }
                  }}
                  className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg border border-slate-300 bg-white text-xs font-semibold text-slate-700 hover:bg-slate-50 transition shadow-2xs self-start sm:self-auto cursor-pointer"
                >
                  <FileText className="w-3.5 h-3.5 text-slate-500" />
                  <span>Export Report (Markdown)</span>
                </button>
              </div>
            </div>

            {/* Tabs Navigation */}
            <div className="border-b border-slate-200 -mx-3 px-3 sm:mx-0 sm:px-0">
              <nav className="flex space-x-2 sm:space-x-6 overflow-x-auto scrollbar-none whitespace-nowrap pb-px">
                {[
                  { id: 'overview', label: 'Overview', icon: <Layers className="w-4 h-4 shrink-0" /> },
                  { id: 'static', label: 'Static Analysis', icon: <FileCode className="w-4 h-4 shrink-0" /> },
                  { id: 'permissions', label: 'Permissions', icon: <Lock className="w-4 h-4 shrink-0" /> },
                  ...(report.dynamic_details ? [{ id: 'dynamic', label: 'Dynamic Sandbox', icon: <Activity className="w-4 h-4 shrink-0" /> }] : []),
                  ...(report.network_details ? [{ id: 'network', label: 'Network Analysis', icon: <Wifi className="w-4 h-4 shrink-0" /> }] : []),
                  { id: 'findings', label: `Findings (${report.findings.length})`, icon: <AlertTriangle className="w-4 h-4 shrink-0" /> },
                  { id: 'evidence', label: 'Evidence Audit', icon: <Terminal className="w-4 h-4 shrink-0" /> },
                ].map(tab => (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id as any)}
                    className={`py-2.5 sm:py-3 px-2.5 sm:px-1 inline-flex items-center space-x-1.5 sm:space-x-2 text-xs sm:text-sm font-semibold border-b-2 transition-colors shrink-0 min-h-[44px] touch-manipulation ${
                      activeTab === tab.id
                        ? 'border-blue-600 text-blue-600'
                        : 'border-transparent text-slate-500 hover:text-slate-700 hover:border-slate-300'
                    }`}
                  >
                    {tab.icon}
                    <span>{tab.label}</span>
                  </button>
                ))}
              </nav>
            </div>

            {/* Tab 1: Overview */}
            {activeTab === 'overview' && (
              <div className="space-y-6">
                {/* Analysis Modules Execution Status */}
                <div className="bg-white rounded-2xl border border-slate-200 p-4 sm:p-6 shadow-xs space-y-4">
                  <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-100 pb-3">
                    <div>
                      <h3 className="text-sm font-bold text-slate-900 flex items-center space-x-2">
                        <Layers className="w-4 h-4 text-blue-600 shrink-0" />
                        <span>Analysis Modules Execution Status</span>
                      </h3>
                      <p className="text-[11px] text-slate-500 mt-0.5">
                        Audit of all static inspection and dynamic sandbox pipelines with verified execution outcomes.
                      </p>
                    </div>
                    {report.analysis_status && (
                      <span className={`text-[11px] font-bold px-2.5 py-1 rounded-full border ${
                        report.analysis_status.startsWith('COMPLETED')
                          ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                          : report.analysis_status === 'PARTIAL'
                          ? 'bg-blue-50 text-blue-700 border-blue-200'
                          : report.analysis_status === 'INCONCLUSIVE'
                          ? 'bg-amber-50 text-amber-700 border-amber-200'
                          : 'bg-rose-50 text-rose-700 border-rose-200'
                      }`}>
                        PIPELINE: {report.analysis_status.replace(/_/g, ' ')}
                      </span>
                    )}
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 sm:gap-4">
                    {/* Static Analysis */}
                    {(() => {
                      const status = report.module_status?.static || (report.static_details ? 'COMPLETED' : 'SKIPPED');
                      const badge = getModuleStatusBadge(status);
                      const errorMsg = report.module_errors?.static || report.static_details?.error_message;
                      return (
                        <div className="p-3.5 sm:p-4 rounded-xl border border-slate-200 bg-white space-y-2">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center space-x-2">
                              <FileCode className="w-4 h-4 text-blue-600 shrink-0" />
                              <span className="text-xs font-bold text-slate-900">Static Code & Manifest Analysis</span>
                              <span className="text-[10px] font-semibold text-slate-400">STAGE 1</span>
                            </div>
                            <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border flex items-center space-x-1 ${badge.badgeClass}`}>
                              {badge.icon}
                              <span>{badge.label}</span>
                            </span>
                          </div>
                          <p className="text-[11px] text-slate-600">
                            {errorMsg || (report.static_details ? 'Manifest, exported components, DEX bytecode indicators, and native binary libraries analyzed.' : 'Static inspection not performed.')}
                          </p>
                          <div className="text-[10px] text-slate-400 pt-1 border-t border-slate-100 flex justify-between">
                            <span>Score: {report.module_scores.static !== null ? `${report.module_scores.static.toFixed(1)} / 100` : 'N/A'}</span>
                            <span>Category: {badge.category}</span>
                          </div>
                        </div>
                      );
                    })()}

                    {/* Permission Analysis */}
                    {(() => {
                      const status = report.module_status?.permissions || (report.permission_details ? 'COMPLETED' : 'SKIPPED');
                      const badge = getModuleStatusBadge(status);
                      const errorMsg = report.module_errors?.permissions || report.permission_details?.error_message;
                      return (
                        <div className="p-3.5 sm:p-4 rounded-xl border border-slate-200 bg-white space-y-2">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center space-x-2">
                              <Lock className="w-4 h-4 text-indigo-600 shrink-0" />
                              <span className="text-xs font-bold text-slate-900">Permission Synergy Evaluation</span>
                              <span className="text-[10px] font-semibold text-slate-400">STAGE 1</span>
                            </div>
                            <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border flex items-center space-x-1 ${badge.badgeClass}`}>
                              {badge.icon}
                              <span>{badge.label}</span>
                            </span>
                          </div>
                          <p className="text-[11px] text-slate-600">
                            {errorMsg || (report.permission_details ? 'Declared Android permissions and dangerous multi-permission synergies evaluated.' : 'Permission evaluation not performed.')}
                          </p>
                          <div className="text-[10px] text-slate-400 pt-1 border-t border-slate-100 flex justify-between">
                            <span>Score: {report.module_scores.permissions !== null ? `${report.module_scores.permissions.toFixed(1)} / 100` : 'N/A'}</span>
                            <span>Category: {badge.category}</span>
                          </div>
                        </div>
                      );
                    })()}

                    {/* Dynamic Sandbox */}
                    {(() => {
                      const status = report.module_status?.dynamic || report.dynamic_details?.status || 'SKIPPED';
                      const badge = getModuleStatusBadge(status);
                      const errorMsg = report.module_errors?.dynamic || report.dynamic_details?.error_message;
                      return (
                        <div className="p-3.5 sm:p-4 rounded-xl border border-slate-200 bg-white space-y-2">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center space-x-2">
                              <Activity className="w-4 h-4 text-emerald-600 shrink-0" />
                              <span className="text-xs font-bold text-slate-900">Emulator Dynamic Sandbox</span>
                              <span className="text-[10px] font-semibold text-slate-400">STAGE 2B</span>
                            </div>
                            <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border flex items-center space-x-1 ${badge.badgeClass}`}>
                              {badge.icon}
                              <span>{badge.label}</span>
                            </span>
                          </div>
                          <p className="text-[11px] text-slate-600 break-words">
                            {errorMsg || (report.dynamic_details?.status === 'COMPLETED' ? 'Target application executed in emulator sandbox; runtime APIs observed.' : 'Dynamic sandbox was not executed or not requested.')}
                          </p>
                          <div className="text-[10px] text-slate-400 pt-1 border-t border-slate-100 flex justify-between">
                            <span>Score: {report.module_scores.dynamic !== null ? `${report.module_scores.dynamic.toFixed(1)} / 100` : 'N/A'}</span>
                            <span>Category: {badge.category}</span>
                          </div>
                        </div>
                      );
                    })()}

                    {/* Network Analysis */}
                    {(() => {
                      const status = report.module_status?.network || report.network_details?.status || 'SKIPPED';
                      const badge = getModuleStatusBadge(status);
                      const errorMsg = report.module_errors?.network || report.network_details?.error_message;
                      return (
                        <div className="p-3.5 sm:p-4 rounded-xl border border-slate-200 bg-white space-y-2">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center space-x-2">
                              <Wifi className="w-4 h-4 text-purple-600 shrink-0" />
                              <span className="text-xs font-bold text-slate-900">Runtime Network Traffic Capture</span>
                              <span className="text-[10px] font-semibold text-slate-400">STAGE 2C</span>
                            </div>
                            <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border flex items-center space-x-1 ${badge.badgeClass}`}>
                              {badge.icon}
                              <span>{badge.label}</span>
                            </span>
                          </div>
                          <p className="text-[11px] text-slate-600 break-words">
                            {errorMsg || (report.network_details && (report.network_details.status === 'COMPLETED' || report.network_details.status === 'NOT_ATTRIBUTED') ? 'Runtime kernel socket tables captured and attributed to UID.' : 'Network runtime capture was not executed or not requested.')}
                          </p>
                          <div className="text-[10px] text-slate-400 pt-1 border-t border-slate-100 flex justify-between">
                            <span>Score: {report.module_scores.network !== null ? `${report.module_scores.network.toFixed(1)} / 100` : 'N/A'}</span>
                            <span>Category: {badge.category}</span>
                          </div>
                        </div>
                      );
                    })()}
                  </div>
                </div>

                {/* Metadata Card */}
                {report.static_details && (
                  <div className="bg-white rounded-2xl border border-slate-200 p-4 sm:p-6 shadow-xs">
                    <h3 className="text-sm font-bold text-slate-900 mb-3 sm:mb-4 flex items-center space-x-2">
                      <Smartphone className="w-4 h-4 text-blue-600 shrink-0" />
                      <span>Package & Manifest Metadata</span>
                    </h3>
                    <div className="grid grid-cols-1 xs:grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3 sm:gap-4 text-xs">
                      <div className="bg-slate-50 p-3 rounded-lg border border-slate-100 min-w-0">
                        <span className="text-slate-400 block mb-0.5">Package Name</span>
                        <span className="font-mono font-medium text-slate-900 break-all block">
                          {report.static_details.package_name || 'N/A'}
                        </span>
                      </div>
                      <div className="bg-slate-50 p-3 rounded-lg border border-slate-100 min-w-0">
                        <span className="text-slate-400 block mb-0.5">Application Name</span>
                        <span className="font-medium text-slate-900 break-words block">
                          {report.static_details.app_name || 'Not Specified'}
                        </span>
                      </div>
                      <div className="bg-slate-50 p-3 rounded-lg border border-slate-100 min-w-0">
                        <span className="text-slate-400 block mb-0.5">Version Name / Code</span>
                        <span className="font-medium text-slate-900 break-words block">
                          {report.static_details.version_name || '1.0'} ({report.static_details.version_code || '1'})
                        </span>
                      </div>
                      <div className="bg-slate-50 p-3 rounded-lg border border-slate-100 min-w-0">
                        <span className="text-slate-400 block mb-0.5">Min / Target SDK</span>
                        <span className="font-medium text-slate-900 block">
                          API {report.static_details.min_sdk || '?'} / API {report.static_details.target_sdk || '?'}
                        </span>
                      </div>
                      <div className="bg-slate-50 p-3 rounded-lg border border-slate-100 min-w-0">
                        <span className="text-slate-400 block mb-0.5">Activities</span>
                        <span className="font-bold text-slate-900 block">{report.static_details.activities.length}</span>
                      </div>
                      <div className="bg-slate-50 p-3 rounded-lg border border-slate-100 min-w-0">
                        <span className="text-slate-400 block mb-0.5">Services</span>
                        <span className="font-bold text-slate-900 block">{report.static_details.services.length}</span>
                      </div>
                      <div className="bg-slate-50 p-3 rounded-lg border border-slate-100 min-w-0">
                        <span className="text-slate-400 block mb-0.5">Receivers</span>
                        <span className="font-bold text-slate-900 block">{report.static_details.receivers.length}</span>
                      </div>
                      <div className="bg-slate-50 p-3 rounded-lg border border-slate-100 min-w-0">
                        <span className="text-slate-400 block mb-0.5">Native Libraries (.so)</span>
                        <span className="font-bold text-slate-900 block truncate" title={report.static_details.native_architectures?.join(', ')}>
                          {report.static_details.native_libraries.length}
                          {report.static_details.native_architectures && report.static_details.native_architectures.length > 0
                            ? ` (${report.static_details.native_architectures.join(', ')})`
                            : ''}
                        </span>
                      </div>
                      <div className="bg-slate-50 p-3 rounded-lg border border-slate-100 min-w-0">
                        <span className="text-slate-400 block mb-0.5">DEX Bytecode</span>
                        <span className="font-bold text-slate-900 block">
                          {report.static_details.dex_file_count ?? 1} file(s) {report.static_details.is_multidex ? '(Multi-DEX)' : ''}
                        </span>
                      </div>
                      <div className="bg-slate-50 p-3 rounded-lg border border-slate-100 min-w-0">
                        <span className="text-slate-400 block mb-0.5">Exported Components</span>
                        <span className="font-bold text-slate-900 block">
                          {report.manifest_config?.exported_components_count ?? report.static_details.exported_components?.length ?? 0}
                          {report.manifest_config?.unprotected_exported_count ? ` (${report.manifest_config.unprotected_exported_count} unprot.)` : ''}
                        </span>
                      </div>
                      <div className="bg-slate-50 p-3 rounded-lg border border-slate-100 min-w-0">
                        <span className="text-slate-400 block mb-0.5">Permissions</span>
                        <span className="font-bold text-slate-900 block">
                          {report.static_details.requested_permissions.length} total
                          {report.manifest_config?.dangerous_permissions_count !== undefined
                            ? ` (${report.manifest_config.dangerous_permissions_count} dangerous)`
                            : ''}
                        </span>
                      </div>
                    </div>

                    {/* Certificate & Manifest Security Details */}
                    <div className="mt-4 pt-4 border-t border-slate-100 grid grid-cols-1 xs:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
                      <div className="bg-slate-50 p-3 rounded-lg border border-slate-100">
                        <span className="text-slate-400 block mb-0.5">Signing Status</span>
                        <span className={`font-semibold ${report.certificate_info?.is_signed ? 'text-emerald-700' : 'text-rose-700'}`}>
                          {report.certificate_info?.is_signed
                            ? `Signed (${report.certificate_info.signature_schemes?.join(', ') || 'V1'})`
                            : 'Unsigned APK'}
                        </span>
                        {report.certificate_info?.verification_status && (
                          <span className="text-[10px] text-slate-500 block mt-0.5 font-mono">
                            Status: {report.certificate_info.verification_status}
                          </span>
                        )}
                      </div>
                      <div className="bg-slate-50 p-3 rounded-lg border border-slate-100">
                        <span className="text-slate-400 block mb-0.5">Keystore & Validity</span>
                        <span className={`font-semibold ${report.certificate_info?.is_debug_key ? 'text-amber-700' : 'text-slate-900'}`}>
                          {report.certificate_info?.is_debug_key ? 'Android Debug Keystore (Unsafe)' : 'Release Keystore'}
                        </span>
                        {report.certificate_info?.valid_until && (
                          <span className="text-[10px] text-slate-500 block mt-0.5 truncate" title={`Valid until: ${report.certificate_info.valid_until}`}>
                            Until: {report.certificate_info.valid_until}
                          </span>
                        )}
                      </div>
                      <div className="bg-slate-50 p-3 rounded-lg border border-slate-100">
                        <span className="text-slate-400 block mb-0.5">Debuggable Build</span>
                        <span className={`font-semibold ${report.manifest_config?.debuggable ? 'text-rose-700' : 'text-emerald-700'}`}>
                          {report.manifest_config?.debuggable ? 'Yes (debuggable="true")' : 'No (Release Build)'}
                        </span>
                        {report.manifest_config?.custom_permissions && report.manifest_config.custom_permissions.length > 0 && (
                          <span className="text-[10px] text-slate-500 block mt-0.5">
                            Custom perms: {report.manifest_config.custom_permissions.length}
                          </span>
                        )}
                      </div>
                      <div className="bg-slate-50 p-3 rounded-lg border border-slate-100">
                        <span className="text-slate-400 block mb-0.5">Cleartext HTTP Traffic</span>
                        <span className={`font-semibold ${report.manifest_config?.uses_cleartext_traffic ? 'text-amber-700' : 'text-slate-900'}`}>
                          {report.manifest_config?.uses_cleartext_traffic ? 'Permitted (Cleartext)' : 'Default / Restricted'}
                        </span>
                        {report.static_details.is_split && (
                          <span className="text-[10px] text-blue-600 block mt-0.5 font-semibold">
                            Split APK ({report.static_details.split_count} splits)
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Intake & Architecture Security Indicators (M3) */}
                    {(report.sha256 || report.framework || (report.native_abis && report.native_abis.length > 0) || (report.coverage_percent !== undefined && report.coverage_percent !== null)) && (
                      <div className="mt-4 pt-4 border-t border-slate-100 grid grid-cols-1 xs:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
                        <div className="bg-slate-50 p-3 rounded-lg border border-slate-100 col-span-1 xs:col-span-2">
                          <span className="text-slate-400 block mb-0.5">Cryptographic Fingerprint (SHA-256)</span>
                          <span className="font-mono text-[11px] text-slate-800 break-all select-all block">
                            {report.sha256 || report.static_details?.sha256 || 'N/A'}
                          </span>
                        </div>
                        <div className="bg-slate-50 p-3 rounded-lg border border-slate-100">
                          <span className="text-slate-400 block mb-0.5">Framework & Runtime</span>
                          <span className="font-semibold text-slate-900 block">
                            {report.framework || report.static_details?.framework || 'Java/Kotlin DEX'}
                          </span>
                        </div>
                        <div className="bg-slate-50 p-3 rounded-lg border border-slate-100">
                          <span className="text-slate-400 block mb-0.5">Target ABIs & Coverage</span>
                          <span className="font-medium text-slate-900 block">
                            {report.native_abis && report.native_abis.length > 0 ? report.native_abis.join(', ') : 'Pure Java / No Native ABI'}
                          </span>
                          {report.coverage_percent !== undefined && report.coverage_percent !== null && (
                            <span className="text-[10px] text-blue-600 block mt-0.5 font-semibold">
                              Coverage: {report.coverage_percent.toFixed(1)}% {report.confidence_score !== undefined && report.confidence_score !== null ? `(Conf: ${report.confidence_score.toFixed(2)})` : ''}
                            </span>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* Key Findings Preview */}
                <div className="bg-white rounded-2xl border border-slate-200 p-4 sm:p-6 shadow-xs space-y-3 sm:space-y-4">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-bold text-slate-900 flex items-center space-x-2">
                      <AlertTriangle className="w-4 h-4 text-blue-600 shrink-0" />
                      <span>Key Surveillance Findings</span>
                    </h3>
                    <button
                      onClick={() => setActiveTab('findings')}
                      className="text-xs font-semibold text-blue-600 hover:text-blue-700 flex items-center space-x-1"
                    >
                      <span>View all findings</span>
                      <ChevronRight className="w-3.5 h-3.5" />
                    </button>
                  </div>

                  <div className="space-y-2.5 sm:space-y-3">
                    {report.findings.slice(0, 5).map((f, idx) => (
                      <div
                        key={idx}
                        className="p-3 sm:p-3.5 rounded-xl border border-slate-200 hover:border-slate-300 transition-colors bg-white flex flex-col sm:flex-row sm:items-start justify-between gap-2.5 sm:gap-3"
                      >
                        <div className="space-y-1 min-w-0 flex-1">
                          <div className="flex items-center space-x-2 flex-wrap gap-y-1">
                            <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border shrink-0 ${getSeverityBadgeClass(f.severity)}`}>
                              {f.severity}
                            </span>
                            <span className="text-xs text-slate-400 font-mono">[{f.category}]</span>
                            <h4 className="text-xs font-bold text-slate-900">{f.title}</h4>
                          </div>
                          <p className="text-xs text-slate-600 leading-relaxed">{f.description}</p>
                          <div className="text-[11px] text-slate-500 font-mono bg-slate-50 px-2.5 py-1 rounded border border-slate-100 inline-block mt-1 break-all max-w-full">
                            Evidence: {f.evidence}
                          </div>
                        </div>
                        <div className="shrink-0 self-start sm:self-auto text-right">
                          <span className="text-xs font-bold px-2 py-1 rounded bg-slate-100 text-slate-700 border border-slate-200">
                            +{f.score} pts
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* Tab 2: Static Analysis */}
            {activeTab === 'static' && (
              <div className="space-y-6">
                {report.static_details ? (
                  <>
                    {/* Specialized Static Indicators Grid */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {/* Boot Receivers */}
                      <div className="bg-white p-5 rounded-2xl border border-slate-200 shadow-xs space-y-3">
                        <div className="flex items-center justify-between">
                          <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center space-x-2">
                            <Activity className="w-4 h-4 text-blue-600" />
                            <span>Boot Persistence Receivers</span>
                          </h4>
                          <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                            report.static_details.boot_completed_receivers.length > 0
                              ? 'bg-amber-50 text-amber-700 border border-amber-200'
                              : 'bg-slate-100 text-slate-500'
                          }`}>
                            {report.static_details.boot_completed_receivers.length} detected
                          </span>
                        </div>
                        {report.static_details.boot_completed_receivers.length > 0 ? (
                          <ul className="text-xs font-mono text-slate-700 space-y-1 bg-slate-50 p-3 rounded-lg border border-slate-100">
                            {report.static_details.boot_completed_receivers.map((r, i) => (
                              <li key={i} className="truncate">• {r}</li>
                            ))}
                          </ul>
                        ) : (
                          <p className="text-xs text-slate-400 italic">No BOOT_COMPLETED receivers registered.</p>
                        )}
                      </div>

                      {/* Accessibility Services */}
                      <div className="bg-white p-5 rounded-2xl border border-slate-200 shadow-xs space-y-3">
                        <div className="flex items-center justify-between">
                          <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center space-x-2">
                            <Eye className="w-4 h-4 text-rose-600" />
                            <span>Accessibility Services</span>
                          </h4>
                          <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                            report.static_details.accessibility_services.length > 0
                              ? 'bg-rose-50 text-rose-700 border border-rose-200'
                              : 'bg-slate-100 text-slate-500'
                          }`}>
                            {report.static_details.accessibility_services.length} detected
                          </span>
                        </div>
                        {report.static_details.accessibility_services.length > 0 ? (
                          <ul className="text-xs font-mono text-rose-700 space-y-1 bg-rose-50/50 p-3 rounded-lg border border-rose-100">
                            {report.static_details.accessibility_services.map((a, i) => (
                              <li key={i} className="truncate font-semibold">• {a}</li>
                            ))}
                          </ul>
                        ) : (
                          <p className="text-xs text-slate-400 italic">No AccessibilityService declared.</p>
                        )}
                      </div>

                      {/* Screen Capture Indicators */}
                      <div className="bg-white p-5 rounded-2xl border border-slate-200 shadow-xs space-y-3">
                        <div className="flex items-center justify-between">
                          <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center space-x-2">
                            <Smartphone className="w-4 h-4 text-blue-600" />
                            <span>Screen Capture / MediaProjection</span>
                          </h4>
                          <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                            report.static_details.screen_capture_indicators.length > 0
                              ? 'bg-rose-50 text-rose-700 border border-rose-200'
                              : 'bg-slate-100 text-slate-500'
                          }`}>
                            {report.static_details.screen_capture_indicators.length} detected
                          </span>
                        </div>
                        {report.static_details.screen_capture_indicators.length > 0 ? (
                          <ul className="text-xs font-mono text-slate-700 space-y-1 bg-slate-50 p-3 rounded-lg border border-slate-100">
                            {report.static_details.screen_capture_indicators.map((s, i) => (
                              <li key={i} className="truncate">• {s}</li>
                            ))}
                          </ul>
                        ) : (
                          <p className="text-xs text-slate-400 italic">No MediaProjection API signatures detected.</p>
                        )}
                      </div>

                      {/* Native Libraries (.so) */}
                      <div className="bg-white p-5 rounded-2xl border border-slate-200 shadow-xs space-y-3">
                        <div className="flex items-center justify-between">
                          <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center space-x-2">
                            <Cpu className="w-4 h-4 text-blue-600" />
                            <span>Native Shared Libraries (.so)</span>
                          </h4>
                          <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-slate-100 text-slate-600">
                            {report.static_details.native_libraries.length} libraries
                          </span>
                        </div>
                        {report.static_details.native_libraries.length > 0 ? (
                          <ul className="text-xs font-mono text-slate-700 space-y-1 bg-slate-50 p-3 rounded-lg border border-slate-100 max-h-40 overflow-y-auto">
                            {report.static_details.native_libraries.map((lib, i) => (
                              <li key={i} className="truncate">• {lib}</li>
                            ))}
                          </ul>
                        ) : (
                          <p className="text-xs text-slate-400 italic">Pure Java/Kotlin bytecode (no native .so binaries).</p>
                        )}
                      </div>
                    </div>

                    {/* Bytecode API Indicators Accordion / Lists */}
                    <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-xs space-y-4">
                      <h4 className="text-sm font-bold text-slate-900 flex items-center space-x-2">
                        <Terminal className="w-4 h-4 text-blue-600" />
                        <span>DEX Bytecode Surveillance API Detection Summary</span>
                      </h4>

                      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
                        <div className="p-3 rounded-xl border border-slate-200 bg-slate-50">
                          <div className="flex justify-between items-center mb-1">
                            <span className="font-semibold text-slate-700">Camera APIs</span>
                            <span className="font-bold text-slate-900">{report.static_details.camera_api_indicators.length}</span>
                          </div>
                          <span className="text-[10px] text-slate-400">Camera / Camera2 calls</span>
                        </div>
                        <div className="p-3 rounded-xl border border-slate-200 bg-slate-50">
                          <div className="flex justify-between items-center mb-1">
                            <span className="font-semibold text-slate-700">Microphone APIs</span>
                            <span className="font-bold text-slate-900">{report.static_details.microphone_api_indicators.length}</span>
                          </div>
                          <span className="text-[10px] text-slate-400">AudioRecord / MediaRecorder</span>
                        </div>
                        <div className="p-3 rounded-xl border border-slate-200 bg-slate-50">
                          <div className="flex justify-between items-center mb-1">
                            <span className="font-semibold text-slate-700">Location APIs</span>
                            <span className="font-bold text-slate-900">{report.static_details.location_api_indicators.length}</span>
                          </div>
                          <span className="text-[10px] text-slate-400">LocationManager / FusedGPS</span>
                        </div>
                        <div className="p-3 rounded-xl border border-slate-200 bg-slate-50">
                          <div className="flex justify-between items-center mb-1">
                            <span className="font-semibold text-slate-700">Telephony & SMS</span>
                            <span className="font-bold text-slate-900">{report.static_details.sms_call_api_indicators.length}</span>
                          </div>
                          <span className="text-[10px] text-slate-400">SmsManager / CallLog</span>
                        </div>
                      </div>

                      {/* Suspicious Commands / Strings */}
                      {report.static_details.suspicious_strings_urls.length > 0 && (
                        <div className="pt-3 border-t border-slate-100">
                          <span className="text-xs font-semibold text-slate-800 block mb-2">
                            Suspicious Shell Commands & Remote Endpoints ({report.static_details.suspicious_strings_urls.length})
                          </span>
                          <div className="bg-slate-900 text-slate-200 p-3 rounded-xl font-mono text-[11px] space-y-1 max-h-48 overflow-y-auto">
                            {report.static_details.suspicious_strings_urls.map((s, i) => (
                              <div key={i} className="truncate text-emerald-400">$ {s}</div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </>
                ) : (
                  <p className="text-sm text-slate-500 italic">No static analysis details available for this report.</p>
                )}
              </div>
            )}

            {/* Tab 3: Permissions */}
            {activeTab === 'permissions' && (
              <div className="space-y-6">
                {report.permission_details ? (
                  <>
                    {/* Synergistic Combination Findings */}
                    <div className="bg-white p-4 sm:p-6 rounded-2xl border border-slate-200 shadow-xs space-y-3 sm:space-y-4">
                      <div className="flex flex-col xs:flex-row xs:items-center justify-between gap-2">
                        <h4 className="text-sm font-bold text-slate-900 flex items-center space-x-2">
                          <ShieldAlert className="w-4 h-4 text-rose-600 shrink-0" />
                          <span>Synergistic Permission Combination Rules</span>
                        </h4>
                        <span className="text-xs px-2.5 py-1 rounded-full bg-rose-50 text-rose-700 border border-rose-200 font-bold shrink-0 self-start xs:self-auto">
                          {report.permission_details.combination_findings.length} Active Synergies
                        </span>
                      </div>

                      {report.permission_details.combination_findings.length > 0 ? (
                        <div className="space-y-3">
                          {report.permission_details.combination_findings.map((combo, i) => (
                            <div
                              key={i}
                              className="p-3.5 sm:p-4 rounded-xl border border-rose-200 bg-rose-50/40 space-y-1.5"
                            >
                              <div className="flex items-center justify-between gap-2">
                                <span className="text-xs font-bold text-rose-900">{combo.title}</span>
                                <span className="text-xs font-bold px-2 py-0.5 rounded bg-rose-600 text-white shrink-0">
                                  +{combo.score} pts
                                </span>
                              </div>
                              <p className="text-xs text-rose-800 leading-relaxed">{combo.description}</p>
                              <div className="text-[11px] text-rose-700 font-mono bg-white/80 p-2 rounded border border-rose-200/60 break-all">
                                {combo.evidence}
                              </div>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <p className="text-xs text-slate-500 italic">
                          No multi-permission surveillance combination patterns triggered.
                        </p>
                      )}
                    </div>

                    {/* Declared Permissions Breakdown */}
                    <div className="bg-white p-4 sm:p-6 rounded-2xl border border-slate-200 shadow-xs space-y-3 sm:space-y-4">
                      <div className="flex items-center justify-between">
                        <h4 className="text-sm font-bold text-slate-900 flex items-center space-x-2">
                          <Lock className="w-4 h-4 text-blue-600 shrink-0" />
                          <span>Declared Android Permissions ({report.permission_details.declared_permissions.length})</span>
                        </h4>
                      </div>

                      <div className="space-y-2">
                        {report.permission_details.declared_permissions.map((perm, idx) => {
                          const matchedFinding = report.permission_details?.individual_findings.find(
                            f => f.evidence.includes(perm) || f.title.includes(perm.split('.').pop() || '')
                          );

                          return (
                            <div
                              key={idx}
                              className="p-3 rounded-xl border border-slate-200 hover:border-slate-300 transition-colors flex flex-col xs:flex-row xs:items-center justify-between gap-2 text-xs"
                            >
                              <div className="space-y-0.5 min-w-0 flex-1">
                                <span className="font-mono font-semibold text-slate-900 break-all block">{perm}</span>
                                {matchedFinding ? (
                                  <p className="text-[11px] text-slate-500">{matchedFinding.description}</p>
                                ) : (
                                  <p className="text-[11px] text-slate-400">Standard / non-sensitive permission</p>
                                )}
                              </div>
                              <div className="shrink-0 self-start xs:self-auto">
                                {matchedFinding ? (
                                  <span className={`px-2 py-1 rounded text-[11px] font-bold border ${getSeverityBadgeClass(matchedFinding.severity)}`}>
                                    +{matchedFinding.score} pts
                                  </span>
                                ) : (
                                  <span className="text-[11px] text-slate-400 px-2 py-1 rounded bg-slate-50 border border-slate-100">
                                    0 pts
                                  </span>
                                )}
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  </>
                ) : (
                  <p className="text-sm text-slate-500 italic">No permission details available.</p>
                )}
              </div>
            )}

            {/* Tab: Dynamic Sandbox (Stage 2B) */}
            {activeTab === 'dynamic' && report.dynamic_details && (() => {
              const dyn = report.dynamic_details;
              const runtimeMap = dyn.runtime_behavior || {};
              const tele = dyn.telemetry;

              const categoriesObserved = tele?.categories_observed ?? Object.values(runtimeMap).filter(r => r.status === 'OBSERVED').length;
              const categoriesTested = tele?.categories_tested ?? (dyn.status === 'COMPLETED' ? 10 : 0);
              const categoriesUnavailable = tele?.categories_unavailable ?? (dyn.status === 'COMPLETED' ? 0 : (dyn.status === 'UNAVAILABLE' ? 10 : 0));
              const categoriesNotTested = tele?.categories_not_tested ?? (dyn.status === 'COMPLETED' ? 0 : 10);
              const surveillanceObserved = tele?.surveillance_observed_count ?? (
                Object.entries(runtimeMap).filter(([k, r]) => k.toUpperCase() !== 'PROCESS' && r.status === 'OBSERVED').length
              );

              const getObsForCategory = (catId: string): RuntimeObservation | undefined => {
                if (tele?.categories) {
                  if (tele.categories[catId]) return tele.categories[catId];
                  if (tele.categories[catId.toUpperCase()]) return tele.categories[catId.toUpperCase()];
                  if (tele.categories[catId.toLowerCase()]) return tele.categories[catId.toLowerCase()];
                }
                if (runtimeMap[catId]) return runtimeMap[catId];
                if (runtimeMap[catId.toUpperCase()]) return runtimeMap[catId.toUpperCase()];
                if (runtimeMap[catId.toLowerCase()]) return runtimeMap[catId.toLowerCase()];
                return undefined;
              };

              return (
                <div className="space-y-6">
                  {/* Executive Sandbox Execution Metadata Card */}
                  <div className="bg-white rounded-2xl border border-slate-200 p-4 sm:p-6 shadow-xs space-y-3 sm:space-y-4">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center space-x-2">
                        <Activity className="w-4 h-4 text-blue-600 shrink-0" />
                        <h4 className="text-sm font-bold text-slate-900">
                          Android Emulator Runtime Telemetry
                        </h4>
                        <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-blue-50 text-blue-700 border border-blue-200 shrink-0">
                          STAGE {dyn.stage || '2B'}
                        </span>
                      </div>
                      <div className="flex items-center space-x-2">
                        {(() => {
                          const badge = getModuleStatusBadge(dyn.status);
                          return (
                            <span className={`text-xs font-bold px-2.5 py-1 rounded-full border flex items-center space-x-1 ${badge.badgeClass}`}>
                              {badge.icon}
                              <span>STATUS: {badge.label}</span>
                            </span>
                          );
                        })()}
                      </div>
                    </div>

                    <div className="grid grid-cols-1 xs:grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                      <div className="bg-slate-50 p-3 rounded-xl border border-slate-100 min-w-0">
                        <span className="text-slate-400 block mb-0.5">Package Executed</span>
                        <span className="font-mono font-semibold text-slate-900 break-all block">
                          {dyn.execution.package_name || 'N/A'}
                        </span>
                      </div>
                      <div className="bg-slate-50 p-3 rounded-xl border border-slate-100 min-w-0">
                        <span className="text-slate-400 block mb-0.5">Launchable Activity</span>
                        <span className="font-mono font-semibold text-slate-900 break-all block">
                          {dyn.execution.launchable_activity || 'None identified'}
                        </span>
                      </div>
                      <div className="bg-slate-50 p-3 rounded-xl border border-slate-100 min-w-0">
                        <span className="text-slate-400 block mb-0.5">Launch Status</span>
                        <div className="flex items-center space-x-1.5 font-semibold">
                          {dyn.execution.launch_success ? (
                            <>
                              <CheckCircle className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                              <span className="text-emerald-700">Successfully Launched</span>
                            </>
                          ) : (
                            <>
                              <XCircle className="w-3.5 h-3.5 text-amber-600 shrink-0" />
                              <span className="text-amber-700">Not Launched</span>
                            </>
                          )}
                        </div>
                      </div>
                      <div className="bg-slate-50 p-3 rounded-xl border border-slate-100 min-w-0">
                        <span className="text-slate-400 block mb-0.5">Observation Window</span>
                        <div className="flex items-center space-x-1.5 font-semibold text-slate-800">
                          <Clock className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                          <span>
                            {(dyn.execution?.duration_seconds ?? 0).toFixed(1)}s
                            {!dyn.execution?.launch_success || (dyn.execution?.duration_seconds ?? 0) === 0 ? ' (Not Launched)' : ''}
                          </span>
                        </div>
                      </div>
                    </div>

                    {/* Behavioral Status Banner */}
                    {dyn.status !== 'COMPLETED' ? (
                      <div className="p-3.5 bg-amber-50/90 border border-amber-200 rounded-xl text-xs text-amber-900 space-y-1.5">
                        <div className="flex items-center space-x-2.5 font-medium">
                          <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0" />
                          <span>
                            Dynamic analysis incomplete (status: <strong className="font-semibold">{dyn.status}</strong>).
                          </span>
                        </div>
                        {dyn.error_message && (
                          <p className="text-amber-800 text-[11px] pl-6.5 font-mono">
                            {dyn.error_message}
                          </p>
                        )}
                        {dyn.limitations && dyn.limitations.length > 0 && !dyn.error_message && (
                          <div className="text-amber-800 text-[11px] pl-6.5">
                            <span className="font-semibold">Limitation: </span>
                            {dyn.limitations[0]}
                          </div>
                        )}
                      </div>
                    ) : surveillanceObserved > 0 ? (
                      <div className="p-3 bg-rose-50 border border-rose-200 rounded-xl text-xs text-rose-800 flex items-center space-x-2.5 font-medium">
                        <ShieldAlert className="w-4 h-4 text-rose-600 shrink-0" />
                        <span>
                          {surveillanceObserved} covert surveillance indicator{surveillanceObserved > 1 ? 's' : ''} confirmed active during runtime observation.
                        </span>
                      </div>
                    ) : categoriesObserved > 0 ? (
                      <div className="p-3 bg-blue-50 border border-blue-200 rounded-xl text-xs text-blue-800 flex items-center space-x-2.5 font-medium">
                        <Activity className="w-4 h-4 text-blue-600 shrink-0" />
                        <span>
                          {categoriesObserved} runtime telemetry category observed active (Runtime Process Lifecycle). No covert surveillance indicators detected.
                        </span>
                      </div>
                    ) : (
                      <div className="p-3 bg-emerald-50 border border-emerald-200 rounded-xl text-xs text-emerald-800 flex items-center space-x-2.5">
                        <ShieldCheck className="w-4 h-4 text-emerald-600 shrink-0" />
                        <span>No suspicious runtime indicators observed during the execution window.</span>
                      </div>
                    )}
                  </div>

                  {/* AVD Pool Execution & Fallback History Card */}
                  <div className="bg-white rounded-2xl border border-slate-200 p-4 sm:p-6 shadow-xs space-y-3">
                    <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-100 pb-2.5">
                      <div className="flex items-center space-x-2">
                        <Smartphone className="w-4 h-4 text-indigo-600 shrink-0" />
                        <h4 className="text-sm font-bold text-slate-900">
                          AVD Pool Execution Profile & Compatibility
                        </h4>
                      </div>
                      <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-100 text-slate-700">
                        Device: {dyn.execution.device_id || 'None'}
                      </span>
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
                      <div className="bg-slate-50 p-3 rounded-xl border border-slate-100">
                        <span className="text-slate-400 block mb-0.5">Target AVD</span>
                        <span className="font-semibold text-slate-900">{dyn.execution.avd_name || 'None'}</span>
                      </div>
                      <div className="bg-slate-50 p-3 rounded-xl border border-slate-100">
                        <span className="text-slate-400 block mb-0.5">Exit Reason</span>
                        <span className="font-mono text-slate-800">{dyn.execution.exit_reason || 'N/A'}</span>
                      </div>
                      <div className="bg-slate-50 p-3 rounded-xl border border-slate-100">
                        <span className="text-slate-400 block mb-0.5">Lifecycle Mode</span>
                        <span className="text-slate-800">
                          {dyn.execution.emulator_started_by_job ? 'Worker Spawned & Cleaned' : 'Reused Online Sandbox'}
                        </span>
                      </div>
                    </div>
                    {dyn.execution.avd_attempts && dyn.execution.avd_attempts.length > 0 && (
                      <div className="space-y-1.5 pt-1">
                        <span className="text-[11px] font-semibold text-slate-700 block">AVD Sequential Fallback Attempts:</span>
                        <div className="space-y-1">
                          {dyn.execution.avd_attempts.map((att, idx) => (
                            <div key={idx} className="flex flex-wrap items-center justify-between gap-2 p-2 rounded-lg bg-slate-50 border border-slate-100 text-[11px]">
                              <div className="flex items-center space-x-2">
                                <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                                  att.status === 'SUCCESS' ? 'bg-emerald-100 text-emerald-800' :
                                  att.status === 'SKIPPED' ? 'bg-slate-200 text-slate-700' :
                                  'bg-rose-100 text-rose-800'
                                }`}>
                                  {att.status}
                                </span>
                                <span className="font-semibold text-slate-900">{att.avd_name}</span>
                                {att.failure_classification && (
                                  <span className="font-mono text-slate-500">[{att.failure_classification}]</span>
                                )}
                              </div>
                              {att.reason && (
                                <span className="text-slate-500 text-[10px] truncate max-w-sm">{att.reason}</span>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Stage 2B Runtime Behavioral Observation Matrix */}
                  <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs space-y-4">
                    <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-100 pb-3">
                      <div>
                        <h4 className="text-sm font-bold text-slate-900 flex items-center space-x-2">
                          <Eye className="w-4 h-4 text-blue-600" />
                          <span>Stage 2B Runtime Behavioral Observation Matrix</span>
                        </h4>
                        <p className="text-[11px] text-slate-400 mt-0.5">
                          Distinguishes statically declared capabilities from operations actually executed during runtime.
                        </p>
                      </div>
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-xs font-semibold px-2.5 py-1 rounded-full bg-slate-100 text-slate-700">
                          Observed: {categoriesObserved} / {RUNTIME_BEHAVIOR_CATEGORIES.length} ({categoriesTested} Tested)
                        </span>
                        {categoriesUnavailable > 0 && (
                          <span className="text-xs font-medium px-2 py-0.5 rounded-full bg-amber-50 text-amber-700 border border-amber-200">
                            {categoriesUnavailable} Unavailable
                          </span>
                        )}
                        {categoriesNotTested > 0 && (
                          <span className="text-xs font-medium px-2 py-0.5 rounded-full bg-blue-50 text-blue-700 border border-blue-200">
                            {categoriesNotTested} Not Tested
                          </span>
                        )}
                      </div>
                    </div>

                    {/* 4-State Canonical Status Legend */}
                    <div className="flex flex-wrap items-center gap-2 sm:gap-3 p-3 bg-slate-50 border border-slate-100 rounded-xl text-xs text-slate-700">
                      <span className="font-semibold text-slate-900 text-[11px]">Legend:</span>
                      <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded-full border bg-rose-100 text-rose-800 border-rose-300 font-bold text-[10px]">
                        <ShieldAlert className="w-3 h-3 text-rose-600" />
                        <span>OBSERVED</span>
                      </span>
                      <span className="text-[10px] text-slate-500 mr-1.5">Runtime event verified</span>
                      <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded-full border bg-slate-100 text-slate-600 border-slate-200 font-medium text-[10px]">
                        <ShieldCheck className="w-3 h-3 text-slate-400" />
                        <span>NOT OBSERVED</span>
                      </span>
                      <span className="text-[10px] text-slate-500 mr-1.5">Monitored; no event</span>
                      <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded-full border bg-amber-50 text-amber-800 border-amber-300 font-medium text-[10px]">
                        <AlertCircle className="w-3 h-3 text-amber-600" />
                        <span>UNAVAILABLE</span>
                      </span>
                      <span className="text-[10px] text-slate-500 mr-1.5">Telemetry failed</span>
                      <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded-full border bg-blue-50 text-blue-700 border-blue-200 font-medium text-[10px]">
                        <Clock className="w-3 h-3 text-blue-500" />
                        <span>NOT TESTED</span>
                      </span>
                      <span className="text-[10px] text-slate-500">Not evaluated</span>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
                      {RUNTIME_BEHAVIOR_CATEGORIES.map(cat => {
                        const obs = getObsForCategory(cat.id);
                        const status = obs?.status || (dyn.status === 'COMPLETED' ? 'NOT_OBSERVED' : 'NOT_TESTED');
                        const badge = getRuntimeStatusBadge(status);
                        const IconComponent = cat.icon;
                        const desc = obs?.description || (
                          status === 'NOT_TESTED'
                            ? 'Category was not evaluated in this analysis run.'
                            : status === 'UNAVAILABLE'
                            ? 'Telemetry source failed or could not be queried reliably.'
                            : cat.fallbackDesc
                        );
                        const source = obs?.source || cat.defaultSource;
                        const evidence = obs?.evidence;
                        const reason = obs?.reason;

                        return (
                          <div
                            key={cat.id}
                            className={`p-4 rounded-xl border transition-all text-xs space-y-2 ${
                              status === 'OBSERVED'
                                ? 'border-rose-300 bg-rose-50/40 shadow-2xs'
                                : status === 'UNAVAILABLE'
                                ? 'border-amber-200 bg-amber-50/20'
                                : status === 'NOT_TESTED'
                                ? 'border-blue-200 bg-blue-50/10'
                                : 'border-slate-200 bg-white hover:border-slate-300'
                            }`}
                          >
                            <div className="flex items-center justify-between">
                              <div className="flex items-center space-x-2 font-semibold text-slate-900">
                                <IconComponent className={`w-4 h-4 ${status === 'OBSERVED' ? 'text-rose-600' : 'text-slate-500'}`} />
                                <span>{cat.label}</span>
                              </div>
                              <span className={`text-[10px] px-2 py-0.5 rounded-full border flex items-center space-x-1 ${badge.badgeClass}`}>
                                {badge.icon}
                                <span>{badge.label}</span>
                              </span>
                            </div>

                            <p className="text-slate-600 text-[11px] leading-relaxed">
                              {desc}
                            </p>

                            <div className="flex items-center justify-between pt-1 border-t border-slate-100/80 text-[10px]">
                              <span className="text-slate-400 font-mono">
                                Source: {source}
                              </span>
                              {reason && (
                                <span className="text-slate-500 text-[10px] italic">
                                  {reason}
                                </span>
                              )}
                            </div>

                            {evidence && (
                              <div className="bg-slate-50 p-2 rounded font-mono text-[10px] text-slate-700 border border-slate-100 break-all">
                                <span className="text-slate-400 font-sans">Trace: </span>{evidence}
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  {/* Discrete Runtime Findings (if any) */}
                  {dyn.findings.length > 0 && (
                    <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs space-y-3">
                      <h4 className="text-sm font-bold text-slate-900 flex items-center space-x-2">
                        <AlertTriangle className="w-4 h-4 text-amber-600" />
                        <span>Dynamic Risk Findings ({dyn.findings.length})</span>
                      </h4>
                      <div className="space-y-2.5">
                        {dyn.findings.map((finding, idx) => (
                          <div
                            key={idx}
                            className="p-3.5 rounded-xl border border-slate-200 bg-slate-50/50 flex items-start justify-between gap-3 text-xs"
                          >
                            <div className="space-y-1">
                              <div className="flex items-center space-x-2">
                                <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${getSeverityBadgeClass(finding.severity)}`}>
                                  {finding.severity}
                                </span>
                                <span className="font-semibold text-slate-900">{finding.title}</span>
                              </div>
                              <p className="text-slate-600 text-[11px]">{finding.description}</p>
                              {finding.evidence && (
                                <p className="font-mono text-[10px] text-slate-500 bg-white p-1.5 rounded border border-slate-100 inline-block">
                                  {finding.evidence}
                                </p>
                              )}
                            </div>
                            <span className="text-xs font-bold px-2 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200 shrink-0">
                              +{finding.score} pts
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Raw Logcat Output Snippet */}
                  {dyn.raw_logcat_snippet && (
                    <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs space-y-3">
                      <h4 className="text-sm font-bold text-slate-900 flex items-center space-x-2">
                        <Terminal className="w-4 h-4 text-blue-600" />
                        <span>Logcat Buffer Sample (Tail)</span>
                      </h4>
                      <pre className="bg-slate-900 text-slate-200 p-4 rounded-xl text-[11px] font-mono overflow-x-auto max-h-60 leading-relaxed">
                        {dyn.raw_logcat_snippet}
                      </pre>
                    </div>
                  )}

                  {/* Stage 2B Sandbox Limitations Notice */}
                  <div className="bg-slate-50 p-4 rounded-xl border border-slate-200 text-xs text-slate-600 space-y-2">
                    <h5 className="font-bold text-slate-800">Stage 2B Telemetry Scope & Limitations:</h5>
                    <ul className="list-disc pl-5 space-y-1 text-slate-500 text-[11px]">
                      {dyn.limitations.map((lim, i) => (
                        <li key={i}>{lim}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              );
            })()}

            {/* Tab: Network Analysis (Stage 2C) */}
            {activeTab === 'network' && report.network_details && (() => {
              const net = report.network_details;
              const obsMap = net.observations || {};
              const attributedObserved = Object.values(obsMap).filter(o => o.status === 'OBSERVED').length;

              return (
                <div className="space-y-6">
                  {/* Executive Network Socket Execution Card */}
                  <div className="bg-white rounded-2xl border border-slate-200 p-4 sm:p-6 shadow-xs space-y-3 sm:space-y-4">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center space-x-2">
                        <Wifi className="w-4 h-4 text-blue-600 shrink-0" />
                        <h4 className="text-sm font-bold text-slate-900">
                          Kernel Socket Telemetry & Target Attribution
                        </h4>
                        <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-blue-50 text-blue-700 border border-blue-200 shrink-0">
                          STAGE {net.stage || '2C'}
                        </span>
                      </div>
                      <div className="flex items-center space-x-2">
                        {(() => {
                          const netBadge = getModuleStatusBadge(net.status);
                          return (
                            <span className={`text-xs font-bold px-2.5 py-1 rounded-full border flex items-center space-x-1 ${netBadge.badgeClass}`}>
                              {netBadge.icon}
                              <span>STATUS: {netBadge.label}</span>
                            </span>
                          );
                        })()}
                        <span className="text-xs font-bold px-2.5 py-1 rounded-full bg-slate-100 text-slate-800 border border-slate-200 shrink-0">
                          SCORE: {net.score !== null ? `${net.score.toFixed(1)} / 100` : 'N/A (Unavailable)'}
                        </span>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 xs:grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                      <div className="bg-slate-50 p-3 rounded-xl border border-slate-100 min-w-0">
                        <span className="text-slate-400 block mb-0.5">Target Package</span>
                        <span className="font-mono font-semibold text-slate-900 break-all block">
                          {net.target_package || 'N/A'}
                        </span>
                      </div>
                      <div className="bg-slate-50 p-3 rounded-xl border border-slate-100 min-w-0">
                        <span className="text-slate-400 block mb-0.5">Target Linux UID</span>
                        <span className="font-mono font-semibold text-slate-900 break-all block">
                          {net.target_uid !== null && net.target_uid !== undefined ? `UID ${net.target_uid}` : 'Unresolved'}
                        </span>
                      </div>
                      <div className="bg-slate-50 p-3 rounded-xl border border-slate-100 min-w-0">
                        <span className="text-slate-400 block mb-0.5">Distinct Connections</span>
                        <span className="font-mono font-semibold text-slate-900 truncate block">
                          {net.distinct_connections_count !== undefined ? `${net.distinct_connections_count} distinct` : `${net.attributed_events_count} distinct`}
                        </span>
                      </div>
                      <div className="bg-slate-50 p-3 rounded-xl border border-slate-100 min-w-0">
                        <span className="text-slate-400 block mb-0.5">Socket Telemetry Samples</span>
                        <div className="flex items-center space-x-1.5 font-semibold text-slate-800">
                          <span className="text-emerald-700 font-bold">{net.total_samples_count ?? net.total_events} samples</span>
                          <span className="text-slate-400">/</span>
                          <span className="text-slate-500">{net.unattributed_events_count} ambient</span>
                        </div>
                      </div>
                    </div>

                    {/* Destination Classification Breakdown */}
                    {net.destination_breakdown && Object.keys(net.destination_breakdown).length > 0 && (
                      <div className="flex flex-wrap items-center gap-2 pt-1 text-xs">
                        <span className="text-slate-400 text-[11px] font-semibold">Destination Types:</span>
                        {Object.entries(net.destination_breakdown).map(([cat, count]) => (
                          <span
                            key={cat}
                            className={`px-2 py-0.5 rounded-full text-[10px] font-bold border ${
                              cat === 'PUBLIC_INTERNET'
                                ? 'bg-amber-50 text-amber-700 border-amber-200'
                                : cat === 'EMULATOR_HOST_GATEWAY'
                                ? 'bg-blue-50 text-blue-700 border-blue-200'
                                : cat === 'PRIVATE_NETWORK'
                                ? 'bg-slate-50 text-slate-700 border-slate-200'
                                : 'bg-slate-100 text-slate-600 border-slate-200'
                            }`}
                          >
                            {cat} ({count})
                          </span>
                        ))}
                      </div>
                    )}

                    {/* Attribution Isolation Banner / Failure Banner */}
                    {net.status !== 'COMPLETED' && net.status !== 'NOT_ATTRIBUTED' ? (
                      <div className="p-3.5 bg-amber-50/90 border border-amber-200 rounded-xl text-xs text-amber-900 space-y-1.5">
                        <div className="flex items-center space-x-2.5 font-medium">
                          <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0" />
                          <span>
                            Runtime network traffic capture unavailable (status: <strong className="font-semibold">{net.status}</strong>). Application execution did not proceed to runtime observation.
                          </span>
                        </div>
                        {net.error_message && (
                          <p className="text-amber-800 text-[11px] pl-6.5 font-mono">
                            {net.error_message}
                          </p>
                        )}
                        {net.limitations && net.limitations.length > 0 && (
                          <div className="text-amber-800 text-[11px] pl-6.5">
                            <span className="font-semibold">Limitation: </span>
                            {net.limitations[0]}
                          </div>
                        )}
                      </div>
                    ) : (
                      <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-600 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div className="flex items-start sm:items-center space-x-2">
                          <ShieldCheck className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5 sm:mt-0" />
                          <span>
                            <strong>Evidence & Context Quality:</strong> Observed socket activity is contextual and not proof of malicious intent. Absence of observed traffic during the observation window does not prove absence of network capability. Ambient emulator traffic ({net.unattributed_events_count} events) is quarantined as NOT_ATTRIBUTED.
                          </span>
                        </div>
                        <span className="text-[10px] font-bold text-slate-500 bg-white px-2 py-0.5 rounded border border-slate-200 shrink-0 self-start sm:self-auto">
                          NO TLS DECRYPTION
                        </span>
                      </div>
                    )}
                  </div>

                  {/* Stage 2C Behavioral Observation Matrix */}
                  <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs space-y-4">
                    <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-100 pb-3">
                      <div>
                        <h4 className="text-sm font-bold text-slate-900 flex items-center space-x-2">
                          <Network className="w-4 h-4 text-blue-600" />
                          <span>Stage 2C Network Behavioral Matrix</span>
                        </h4>
                        <p className="text-[11px] text-slate-400 mt-0.5">
                          Audits transport-level socket indicators with verified UID ownership.
                        </p>
                      </div>
                      <span className="text-xs font-semibold px-2.5 py-1 rounded-full bg-slate-100 text-slate-700">
                        {attributedObserved} / {NETWORK_BEHAVIOR_CATEGORIES.length} Observed
                      </span>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      {NETWORK_BEHAVIOR_CATEGORIES.map(cat => {
                        const obs = obsMap[cat.id];
                        const isNetAvailable = net.status === 'COMPLETED' || net.status === 'NOT_ATTRIBUTED';
                        const status = isNetAvailable ? (obs?.status || 'NOT_OBSERVED') : 'NOT_AVAILABLE';
                        const IconComponent = cat.icon;

                        const isObserved = status === 'OBSERVED';
                        const isNotAvailable = status === 'NOT_AVAILABLE';

                        return (
                          <div
                            key={cat.id}
                            className={`p-4 rounded-xl border transition-all ${
                              isObserved
                                ? 'border-amber-300 bg-amber-50/40 shadow-xs'
                                : isNotAvailable
                                ? 'border-blue-100 bg-blue-50/20'
                                : 'border-slate-200 bg-white'
                            }`}
                          >
                            <div className="flex items-start justify-between gap-2">
                              <div className="flex items-center space-x-2.5">
                                <div className={`p-1.5 rounded-lg ${
                                  isObserved
                                    ? 'bg-amber-100 text-amber-700'
                                    : isNotAvailable
                                    ? 'bg-blue-100 text-blue-600'
                                    : 'bg-slate-100 text-slate-500'
                                }`}>
                                  <IconComponent className="w-4 h-4" />
                                </div>
                                <div>
                                  <h5 className="text-xs font-bold text-slate-900">{cat.label}</h5>
                                  <span className="text-[10px] text-slate-400 font-mono">
                                    Source: {obs?.source || cat.defaultSource}
                                  </span>
                                </div>
                              </div>
                              <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border shrink-0 ${
                                isObserved
                                  ? 'bg-amber-100 text-amber-800 border-amber-300'
                                  : isNotAvailable
                                  ? 'bg-blue-50 text-blue-700 border-blue-200'
                                  : 'bg-slate-100 text-slate-500 border-slate-200'
                              }`}>
                                {status}
                              </span>
                            </div>

                            <p className="text-[11px] text-slate-600 mt-2 leading-relaxed">
                              {!isNetAvailable
                                ? 'Runtime socket telemetry is unavailable because application was not executed.'
                                : obs?.description || (net.attributed_events_count === 0 ? 'No socket activity attributed to target app during observation window (absence of traffic does not prove absence of network capability).' : cat.fallbackDesc)}
                            </p>

                            {isNetAvailable && obs?.evidence && (
                              <div className="mt-2 text-[10px] font-mono text-slate-700 bg-white/80 p-2 rounded border border-slate-200/60 break-all">
                                <strong className="text-slate-500">Evidence:</strong> {obs.evidence}
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  {/* Captured Network Events Table */}
                  <div className="bg-white rounded-2xl border border-slate-200 p-4 sm:p-6 shadow-xs space-y-3 sm:space-y-4">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-100 pb-3">
                      <div>
                        <h4 className="text-sm font-bold text-slate-900 flex items-center space-x-2">
                          <Terminal className="w-4 h-4 text-blue-600 shrink-0" />
                          <span>Kernel Socket Events ({net.events.length})</span>
                        </h4>
                        <p className="text-[11px] text-slate-400 mt-0.5">
                          Direct telemetry from /proc/net/ decoded with UID attribution metadata.
                        </p>
                      </div>
                      <div className="flex items-center space-x-2 shrink-0 self-start sm:self-auto">
                        <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200">
                          {net.attributed_events_count} ATTRIBUTED
                        </span>
                        <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-slate-100 text-slate-600 border border-slate-200">
                          {net.unattributed_events_count} QUARANTINED
                        </span>
                      </div>
                    </div>

                    {net.events.length > 0 ? (
                      <div className="overflow-x-auto scrollbar-thin">
                        <table className="min-w-[680px] w-full text-left text-xs whitespace-nowrap">
                          <thead>
                            <tr className="border-b border-slate-200 bg-slate-50/50 text-[11px] font-semibold text-slate-500">
                              <th className="py-2.5 px-3">Proto</th>
                              <th className="py-2.5 px-3">Local Address</th>
                              <th className="py-2.5 px-3">Remote Destination</th>
                              <th className="py-2.5 px-3">Dest Type</th>
                              <th className="py-2.5 px-3">Samples</th>
                              <th className="py-2.5 px-3">State</th>
                              <th className="py-2.5 px-3">Kernel UID</th>
                              <th className="py-2.5 px-3 text-right">Attribution</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-100 font-mono text-[11px]">
                            {net.events.map((ev, idx) => (
                              <tr key={idx} className={ev.attribution_status === 'ATTRIBUTED' ? 'bg-amber-50/20' : ''}>
                                <td className="py-2.5 px-3 font-bold text-slate-700">{ev.protocol}</td>
                                <td className="py-2.5 px-3 text-slate-600">{ev.local_address}:{ev.local_port}</td>
                                <td className="py-2.5 px-3 font-semibold text-slate-900">
                                  <span>{ev.remote_address}:{ev.remote_port}</span>
                                  {ev.http_confirmed === true && (
                                    <span className="ml-1.5 px-1.5 py-0.5 rounded text-[9px] font-sans font-bold bg-amber-100 text-amber-800 border border-amber-300">
                                      HTTP CONFIRMED
                                    </span>
                                  )}
                                  {ev.http_confirmed === false && (
                                    <span className="ml-1.5 px-1.5 py-0.5 rounded text-[9px] font-sans font-bold bg-slate-100 text-slate-600 border border-slate-200">
                                      NOT HTTP
                                    </span>
                                  )}
                                  {ev.http_confirmed === null && (ev.remote_port === 80 || ev.remote_port === 8080 || ev.remote_port === 8765) && (
                                    <span className="ml-1.5 px-1.5 py-0.5 rounded text-[9px] font-sans font-bold bg-blue-50 text-blue-700 border border-blue-200">
                                      PORT ONLY
                                    </span>
                                  )}
                                </td>
                                <td className="py-2.5 px-3">
                                  <span className="px-1.5 py-0.5 rounded text-[10px] font-sans font-medium bg-slate-100 text-slate-700 border border-slate-200">
                                    {ev.destination_category || 'UNKNOWN'}
                                  </span>
                                </td>
                                <td className="py-2.5 px-3 font-mono text-slate-500">
                                  {ev.samples_count ? `x${ev.samples_count}` : 'x1'}
                                </td>
                                <td className="py-2.5 px-3 text-slate-500">{ev.state || 'N/A'}</td>
                                <td className="py-2.5 px-3 text-slate-600">UID {ev.uid !== null ? ev.uid : 'N/A'}</td>
                                <td className="py-2.5 px-3 text-right">
                                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold font-sans border ${
                                    ev.attribution_status === 'ATTRIBUTED'
                                      ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                                      : 'bg-slate-100 text-slate-500 border-slate-200'
                                  }`}>
                                    {ev.attribution_status}
                                  </span>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    ) : (
                      <p className="text-xs text-slate-400 italic">No network socket events captured.</p>
                    )}
                  </div>

                  {/* Stage 2C Defensive Limitations */}
                  <div className="bg-slate-50 p-4 rounded-xl border border-slate-200 text-xs text-slate-600 space-y-2">
                    <h5 className="font-bold text-slate-800">Stage 2C Telemetry Guarantees & Limitations:</h5>
                    <ul className="list-disc pl-5 space-y-1 text-slate-500 text-[11px]">
                      {net.limitations.map((lim, i) => (
                        <li key={i}>{lim}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              );
            })()}

            {/* Tab 4: Findings */}
            {activeTab === 'findings' && (
              <div className="space-y-4">
                {/* Search & Severity Filter Bar */}
                <div className="bg-white p-3.5 sm:p-4 rounded-xl border border-slate-200 shadow-xs flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-2.5 sm:gap-3">
                  <div className="relative w-full sm:w-72">
                    <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
                    <input
                      type="text"
                      placeholder="Search findings or evidence..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="w-full pl-9 pr-3 py-1.5 text-xs rounded-lg border border-slate-200 focus:outline-none focus:border-blue-500 min-h-[36px]"
                    />
                  </div>

                  <div className="flex items-center space-x-1 w-full sm:w-auto overflow-x-auto scrollbar-none pb-1 sm:pb-0">
                    {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map(sev => (
                      <button
                        key={sev}
                        onClick={() => setFindingSeverityFilter(sev)}
                        className={`px-2.5 py-1.5 rounded-md text-[11px] font-semibold transition-colors shrink-0 min-h-[34px] ${
                          findingSeverityFilter === sev
                            ? 'bg-blue-600 text-white'
                            : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                        }`}
                      >
                        {sev}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Findings List */}
                <div className="space-y-3">
                  {filteredFindings.map((f, i) => (
                    <div
                      key={i}
                      className="bg-white p-4 sm:p-5 rounded-2xl border border-slate-200 shadow-xs hover:border-slate-300 transition-colors space-y-2 sm:space-y-2.5"
                    >
                      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-2 sm:gap-3">
                        <div className="space-y-1 min-w-0 flex-1">
                          <div className="flex items-center space-x-2 flex-wrap gap-y-1">
                            <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border shrink-0 ${getSeverityBadgeClass(f.severity)}`}>
                              {f.severity}
                            </span>
                            <span className="text-xs font-mono text-slate-400">[{f.category}]</span>
                            {f.rule_id && (
                              <span className="text-[10px] font-mono text-slate-600 bg-slate-100 px-1.5 py-0.5 rounded border border-slate-200">
                                {f.rule_id}
                              </span>
                            )}
                            {f.confidence !== undefined && f.confidence !== null && (
                              <span className="text-[10px] font-medium text-slate-500">
                                ({Math.round(f.confidence * 100)}% confidence)
                              </span>
                            )}
                            <h4 className="text-sm font-bold text-slate-900">{f.title}</h4>
                          </div>
                          <p className="text-xs text-slate-600 leading-relaxed">{f.description}</p>
                        </div>
                        <div className="shrink-0 self-start sm:self-auto text-right">
                          <span className="text-xs font-bold px-2.5 py-1 rounded-lg bg-slate-100 text-slate-800 border border-slate-200">
                            +{f.score} pts
                          </span>
                        </div>
                      </div>

                      <div className="bg-slate-50 p-2.5 rounded-lg border border-slate-100 text-[11px] font-mono text-slate-700 break-all">
                        <strong className="text-slate-500">Evidence{f.evidence_source ? ` (${f.evidence_source})` : ''}:</strong> {f.evidence}
                      </div>

                      {f.remediation && (
                        <div className="bg-emerald-50/60 p-2.5 rounded-lg border border-emerald-100 text-[11px] text-emerald-800 leading-relaxed">
                          <strong className="text-emerald-900 font-semibold">Remediation:</strong> {f.remediation}
                        </div>
                      )}
                    </div>
                  ))}

                  {filteredFindings.length === 0 && (
                    <div className="text-center py-12 bg-white rounded-2xl border border-slate-200">
                      <p className="text-xs text-slate-400">No findings matched your filter or search query.</p>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Tab 5: Evidence */}
            {activeTab === 'evidence' && (
              <div className="bg-white rounded-2xl border border-slate-200 shadow-xs overflow-hidden">
                <div className="p-4 border-b border-slate-100">
                  <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                    Technical Evidence Audit Trail
                  </h4>
                  <p className="text-[11px] text-slate-400">
                    Comprehensive log of all signatures, manifest tags, runtime logcat hits, and permission indicators extracted.
                  </p>
                </div>
                <div className="overflow-x-auto scrollbar-thin">
                  <table className="min-w-[640px] w-full text-xs text-left whitespace-nowrap">
                    <thead className="bg-slate-50 border-b border-slate-200 text-slate-500 font-semibold">
                      <tr>
                        <th className="py-2.5 px-4">Category</th>
                        <th className="py-2.5 px-4">Severity</th>
                        <th className="py-2.5 px-4">Finding Title</th>
                        <th className="py-2.5 px-4">Technical Evidence</th>
                        <th className="py-2.5 px-4 text-right">Contribution</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                      {report.findings.map((f, i) => (
                        <tr key={i} className="hover:bg-slate-50/60 transition-colors">
                          <td className="py-2.5 px-4 font-mono text-slate-500">{f.category}</td>
                          <td className="py-2.5 px-4">
                            <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${getSeverityBadgeClass(f.severity)}`}>
                              {f.severity}
                            </span>
                          </td>
                          <td className="py-2.5 px-4 font-semibold text-slate-800">{f.title}</td>
                          <td className="py-2.5 px-4 font-mono text-slate-600 max-w-md truncate" title={f.evidence}>
                            {f.evidence}
                          </td>
                          <td className="py-2.5 px-4 text-right font-bold text-slate-700">+{f.score}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

          </section>
        )}

      </main>

      {/* Manual Permission Sandbox Modal */}
      {showPermSandbox && (
        <div className="fixed inset-0 z-50 bg-slate-900/40 backdrop-blur-2xs flex items-center justify-center p-3 sm:p-4">
          <div className="bg-white rounded-2xl border border-slate-200 shadow-xl max-w-lg w-full p-4 sm:p-6 space-y-3 sm:space-y-4 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between">
              <h3 className="text-sm sm:text-base font-bold text-slate-900 flex items-center space-x-2">
                <Sliders className="w-5 h-5 text-blue-600 shrink-0" />
                <span>Permission Risk Sandbox</span>
              </h3>
              <button
                onClick={() => setShowPermSandbox(false)}
                className="w-8 h-8 rounded-lg flex items-center justify-center text-slate-400 hover:text-slate-600 hover:bg-slate-100 font-bold text-lg"
              >
                ✕
              </button>
            </div>

            <p className="text-xs text-slate-600">
              Input one Android permission per line to evaluate the standalone Permission Risk Engine and surveillance combination rules without uploading an APK.
            </p>

            <textarea
              rows={6}
              value={manualPermsInput}
              onChange={(e) => setManualPermsInput(e.target.value)}
              className="w-full text-xs font-mono p-3 rounded-xl border border-slate-300 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              placeholder="android.permission.CAMERA..."
            />

            <div className="flex flex-col-reverse sm:flex-row sm:justify-end gap-2 sm:gap-3 pt-2">
              <button
                onClick={() => setShowPermSandbox(false)}
                className="w-full sm:w-auto px-4 py-2.5 text-xs font-semibold rounded-lg text-slate-600 hover:bg-slate-100 min-h-[44px]"
              >
                Cancel
              </button>
              <button
                onClick={runManualPermissionsAnalysis}
                disabled={isAnalyzing}
                className="w-full sm:w-auto px-4 py-2.5 text-xs font-semibold rounded-lg bg-blue-600 hover:bg-blue-700 text-white shadow-xs min-h-[44px]"
              >
                Evaluate Permissions
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Footer */}
      <footer className="bg-white border-t border-slate-200 py-6 mt-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center text-xs text-slate-400 space-y-1">
          <p className="font-medium text-slate-600">SpyAware Analyzer • Standalone Defensive Platform</p>
          <p>
            Designed for covert surveillance detection. Integration ready via REST API for Android SpyAware client.
          </p>
        </div>
      </footer>
    </div>
  );
}

export default App;
