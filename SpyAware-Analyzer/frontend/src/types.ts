export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface Finding {
  category: string;
  severity: Severity;
  title: string;
  description: string;
  evidence: string;
  score: number;
  finding_id?: string | null;
  rule_id?: string | null;
  confidence?: number;
  evidence_source?: string;
  location?: string | null;
  security_impact?: string | null;
  false_positive_notes?: string | null;
  remediation?: string | null;
  detection_method?: string;
}

export interface ExportedComponent {
  component_type: string;
  name: string;
  exported: boolean;
  permission?: string | null;
}

export interface CertificateInfo {
  is_signed: boolean;
  signature_schemes: string[];
  issuer?: string | null;
  subject?: string | null;
  sha256_fingerprint?: string | null;
  sha1_fingerprint?: string | null;
  serial_number?: string | null;
  valid_from?: string | null;
  valid_until?: string | null;
  signature_algorithm?: string | null;
  verification_status?: string | null;
  verification_details?: string | null;
  is_debug_key: boolean;
}

export interface ManifestConfiguration {
  debuggable: boolean;
  allow_backup: boolean;
  uses_cleartext_traffic?: boolean | null;
  network_security_config?: string | null;
  has_custom_permissions: boolean;
  custom_permissions?: string[];
  dangerous_permissions_count?: number;
  exported_components_count?: number;
  unprotected_exported_count?: number;
}

export interface StaticAnalysisResult {
  apk_filename: string;
  package_name?: string | null;
  app_name?: string | null;
  version_name?: string | null;
  version_code?: string | null;
  min_sdk?: string | null;
  target_sdk?: string | null;
  launchable_activity?: string | null;
  requested_permissions: string[];
  activities: string[];
  services: string[];
  receivers: string[];
  providers: string[];
  exported_components: ExportedComponent[];
  foreground_service_indicators: string[];
  boot_completed_receivers: string[];
  accessibility_services: string[];
  overlay_capabilities: string[];
  camera_api_indicators: string[];
  microphone_api_indicators: string[];
  location_api_indicators: string[];
  sms_call_api_indicators: string[];
  contacts_api_indicators: string[];
  screen_capture_indicators: string[];
  network_api_indicators: string[];
  native_libraries: string[];
  native_architectures?: string[];
  dex_file_count?: number;
  dex_files_analyzed?: string[];
  dex_files_failed?: Record<string, string>;
  is_multidex?: boolean;
  suspicious_strings_urls: string[];
  findings: Finding[];
  score: number;
  is_valid_apk: boolean;
  error_message?: string | null;
  certificate_info?: CertificateInfo | null;
  manifest_config?: ManifestConfiguration | null;
  is_split?: boolean;
  split_count?: number;
  limitations?: string[];
  sha256?: string | null;
  sha1?: string | null;
  md5?: string | null;
  file_size_bytes?: number | null;
  framework?: string | null;
  framework_details?: Record<string, any> | null;
  packing_info?: Record<string, any> | null;
  max_sdk?: string | null;
}

export interface PermissionAnalysisResult {
  declared_permissions: string[];
  individual_findings: Finding[];
  combination_findings: Finding[];
  findings: Finding[];
  score: number;
  error_message?: string | null;
}

export interface Observation {
  type: string;
  severity: Severity;
  description: string;
  evidence?: string | null;
  timestamp?: string | null;
}

export type RuntimeBehaviorStatus =
  | 'OBSERVED'
  | 'NOT_OBSERVED'
  | 'UNAVAILABLE'
  | 'NOT_TESTED'
  | 'NOT_AVAILABLE'
  | 'ERROR';

export interface RuntimeObservation {
  category: string;
  name?: string | null;
  status: RuntimeBehaviorStatus;
  description: string;
  evidence?: string | null;
  timestamp?: string | null;
  confidence?: number;
  source: string;
  reason?: string | null;
  details?: Record<string, any> | null;
}

export interface CanonicalTelemetryResult {
  categories_observed: number;
  categories_tested: number;
  categories_unavailable: number;
  categories_not_tested: number;
  categories_total: number;
  categories: Record<string, RuntimeObservation>;
  surveillance_observed_count: number;
  headline: string;
  summary: string;
  additional_findings: Finding[];
}

export interface AVDFallbackAttempt {
  avd_name: string;
  status: 'ATTEMPTED' | 'SUCCESS' | 'SKIPPED' | 'FAILED' | string;
  failure_classification?: string | null;
  reason?: string | null;
  duration_seconds: number;
}

export interface AVDProfile {
  name: string;
  display_name?: string | null;
  target: string;
  api_level?: number | null;
  android_version?: string | null;
  abis: string[];
  system_image_dir?: string | null;
  system_image_installed: boolean;
  ready: boolean;
  error_message?: string | null;
  is_running: boolean;
  device_serial?: string | null;
}

export interface AVDInventory {
  profiles: AVDProfile[];
  installed_system_images: string[];
  available_avd_names: string[];
  running_devices: string[];
  emulator_available: boolean;
  adb_available: boolean;
  recommended_targets: Array<Record<string, any>>;
}

export interface ExecutionMetadata {
  package_name?: string | null;
  launchable_activity?: string | null;
  launch_success: boolean;
  duration_seconds: number;
  avd_name?: string | null;
  device_id?: string | null;
  emulator_started_by_job: boolean;
  exit_reason?: string | null;
  selected_avd_reason?: string | null;
  avd_attempts?: AVDFallbackAttempt[];
}

export interface EnvironmentStatus {
  adb_available: boolean;
  emulator_available: boolean;
  avdmanager_available: boolean;
  frida_available?: boolean;
  available_avds: string[];
  running_devices: string[];
  selected_avd?: string | null;
  ready: boolean;
  message: string;
}

export interface DynamicAnalysisResult {
  module: string;
  stage?: string;
  status: string;
  score: number | null;
  risk_level: string;
  execution: ExecutionMetadata;
  observations: Observation[];
  findings: Finding[];
  runtime_behavior?: Record<string, RuntimeObservation>;
  telemetry?: CanonicalTelemetryResult | null;
  limitations: string[];
  error_message?: string | null;
  raw_logcat_snippet?: string | null;
}

export interface ModuleScores {
  static: number | null;
  permissions: number | null;
  dynamic: number | null;
  network: number | null;
  ble: number | null;
}

export interface NetworkEvent {
  timestamp: number;
  protocol: string;
  local_address: string;
  local_port: number;
  remote_address: string;
  remote_port: number;
  state?: string | null;
  package_name?: string | null;
  uid?: number | null;
  pid?: number | null;
  attribution_status: 'ATTRIBUTED' | 'NOT_ATTRIBUTED' | 'UNKNOWN';
  source: string;
  evidence?: string | null;
  confidence: number;
  destination_category?: string;
  connection_id?: string | null;
  samples_count?: number;
  http_confirmed?: boolean | null;
  protocol_evidence?: string | null;
}

export interface NetworkObservation {
  category: string;
  status: string;
  description: string;
  evidence?: string | null;
  count: number;
  confidence: number;
  source: string;
}

export interface NetworkAnalysisResult {
  module: string;
  stage: string;
  status: string;
  score: number | null;
  risk_level: string;
  target_package?: string | null;
  target_uid?: number | null;
  target_pids?: number[];
  duration_seconds: number;
  total_events: number;
  attributed_events_count: number;
  unattributed_events_count: number;
  distinct_connections_count?: number;
  total_samples_count?: number;
  destination_breakdown?: Record<string, number>;
  events: NetworkEvent[];
  observations: Record<string, NetworkObservation>;
  findings: Finding[];
  limitations: string[];
  error_message?: string | null;
}

export interface RiskReport {
  analysis_id: string;
  timestamp: string;
  apk_filename: string;
  overall_score: number;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'UNKNOWN';
  analysis_status?: 'COMPLETED_CLEAN' | 'COMPLETED_WITH_FINDINGS' | 'PARTIAL' | 'FAILED' | 'INCONCLUSIVE' | string;
  module_scores: ModuleScores;
  module_status?: Record<string, string>;
  module_errors?: Record<string, string | null>;
  findings: Finding[];
  summary: string;
  disclaimer: string;
  is_split?: boolean;
  split_count?: number;
  split_names?: string[];
  dex_file_count?: number;
  dex_files_analyzed?: string[];
  limitations?: string[];
  certificate_info?: CertificateInfo | null;
  manifest_config?: ManifestConfiguration | null;
  static_details?: StaticAnalysisResult | null;
  permission_details?: PermissionAnalysisResult | null;
  dynamic_details?: DynamicAnalysisResult | null;
  network_details?: NetworkAnalysisResult | null;
  sha256?: string | null;
  framework?: string | null;
  native_abis?: string[];
  has_native_libraries?: boolean;
  coverage_percent?: number | null;
  confidence_score?: number | null;
  correlation_summary?: Record<string, any> | null;
  compatibility_details?: CompatibilityReport | null;
  analysis_profile?: 'QUICK' | 'STANDARD' | 'EXTENDED' | 'STATIC_ONLY' | string;
  duration_seconds?: number | null;
  export_markdown_url?: string | null;
  export_json_url?: string | null;
}

export interface ConnectedDevice {
  serial: string;
  state: 'device' | 'offline' | 'unauthorized' | 'authorizing' | 'recovery' | 'missing' | 'unknown' | string;
  is_authorized: boolean;
  is_online: boolean;
  device_type: 'EMULATOR' | 'PHYSICAL' | 'UNKNOWN';
  model?: string | null;
  product?: string | null;
  android_version?: string | null;
  api_level?: number | null;
  abi?: string | null;
  supported_abis?: string[];
  avd_name?: string | null;
}

export interface DiscoveredPackage {
  package_name: string;
  app_name?: string | null;
  version_name?: string | null;
  version_code?: string | null;
  is_system: boolean;
  is_split: boolean;
  base_apk_path?: string | null;
  split_apk_paths?: string[];
  split_count: number;
  apk_size_bytes?: number | null;
  extraction_permitted: boolean;
  extraction_error?: string | null;
}

export interface RecentAnalysisItem {
  analysis_id: string;
  timestamp: string;
  apk_filename: string;
  overall_score: number;
  risk_level: string;
}

export interface InstalledAppInfo {
  packageName: string;
  appName: string;
  versionName: string;
  isSystem: boolean;
  isSplit: boolean;
  splitCount: number;
  splitNames?: string[];
  apkSize: number;
  icon?: string | null;
}

export interface NativeUploadProgress {
  percent: number;
  stage: string;
}

export type CompatibilityStatus =
  | 'COMPATIBLE'
  | 'COMPATIBLE_WITH_WARNINGS'
  | 'INCOMPATIBLE_ABI'
  | 'INCOMPATIBLE_ANDROID_VERSION'
  | 'REQUIRED_SPLIT_PACKAGES_MISSING'
  | 'REQUIRED_CAPABILITY_UNAVAILABLE'
  | 'COMPATIBILITY_UNKNOWN';

export interface CandidateEnvironmentEvaluation {
  target_id: string;
  target_type: string;
  display_name: string;
  api_level?: number | null;
  android_version?: string | null;
  supported_abis: string[];
  is_running: boolean;
  is_booted: boolean;
  status: CompatibilityStatus;
  rank_score: number;
  rationale: string;
  rejection_reason?: string | null;
  warnings: string[];
}

export interface CompatibilityReport {
  overall_status: CompatibilityStatus;
  apk_package_name?: string | null;
  apk_min_sdk?: number | null;
  apk_target_sdk?: number | null;
  apk_native_abis: string[];
  is_pure_java: boolean;
  selected_target?: CandidateEnvironmentEvaluation | null;
  candidate_evaluations: CandidateEnvironmentEvaluation[];
  warnings: string[];
  errors: string[];
  setup_instructions?: string | null;
}

export type FindingDiffStatus = 'ADDED' | 'REMOVED' | 'MODIFIED' | 'UNCHANGED';

export type AnalysisRelationship =
  | 'SAME_APK_EXACT'
  | 'SAME_PACKAGE_VERSION_UPDATE'
  | 'SAME_PACKAGE_SAME_VERSION'
  | 'UNRELATED_APKS'
  | 'UNKNOWN';

export interface FindingDiff {
  finding_key: string;
  status: FindingDiffStatus;
  category: string;
  title: string;
  base_finding?: Finding | null;
  target_finding?: Finding | null;
  base_severity?: Severity | null;
  target_severity?: Severity | null;
  base_score?: number | null;
  target_score?: number | null;
  score_delta: number;
  confidence_delta: number;
  description?: string | null;
}

export interface ModuleScoreDiff {
  module_name: string;
  base_score?: number | null;
  target_score?: number | null;
  score_delta?: number | null;
  base_status?: string | null;
  target_status?: string | null;
  status_changed: boolean;
}

export interface PackageIdentityDiff {
  relationship: AnalysisRelationship;
  base_package_name?: string | null;
  target_package_name?: string | null;
  is_package_changed: boolean;
  base_version?: string | null;
  target_version?: string | null;
  is_version_changed: boolean;
  base_sha256?: string | null;
  target_sha256?: string | null;
  is_hash_identical: boolean;
  base_min_sdk?: string | null;
  target_min_sdk?: string | null;
  base_target_sdk?: string | null;
  target_target_sdk?: string | null;
  base_cert_sha256?: string | null;
  target_cert_sha256?: string | null;
  is_cert_changed: boolean;
  warnings: string[];
}

export interface CoverageDiff {
  base_dex_count: number;
  target_dex_count: number;
  dex_count_delta: number;
  base_permissions_count: number;
  target_permissions_count: number;
  permissions_count_delta: number;
  base_components_count: number;
  target_components_count: number;
  components_count_delta: number;
  base_dynamic_status?: string | null;
  target_dynamic_status?: string | null;
  dynamic_depth_changed: boolean;
  base_coverage_percent?: number | null;
  target_coverage_percent?: number | null;
  coverage_percent_delta?: number | null;
  base_confidence_score?: number | null;
  target_confidence_score?: number | null;
  confidence_score_delta?: number | null;
  notes: string[];
}

export interface ComparisonRequest {
  base_analysis_id: string;
  target_analysis_id: string;
}

export interface AnalysisComparisonReport {
  base_analysis_id: string;
  target_analysis_id: string;
  base_apk_filename: string;
  target_apk_filename: string;
  timestamp_comparison: string;
  package_identity: PackageIdentityDiff;
  overall_score_base: number;
  overall_score_target: number;
  overall_score_delta: number;
  risk_level_base: string;
  risk_level_target: string;
  analysis_status_base: string;
  analysis_status_target: string;
  module_diffs: Record<string, ModuleScoreDiff>;
  findings_summary: Record<string, number>;
  added_findings: FindingDiff[];
  removed_findings: FindingDiff[];
  modified_findings: FindingDiff[];
  unchanged_findings: FindingDiff[];
  coverage_diff: CoverageDiff;
  is_unrelated_warning: boolean;
  summary: string;
}

declare global {
  interface Window {
    SpyAwareBridge?: {
      getBackendUrl?: () => string;
      getAppVersion?: () => string;
      reportConnectionStatus?: (online: boolean, message: string) => void;
      isNativeWrapper?: () => boolean;
      getInstalledApps?: (includeSystem: boolean) => string;
      checkSplitStatus?: (packageName: string) => string;
      analyzeInstalledApp?: (packageName: string, dynamic: boolean, network: boolean) => void;
      cancelAnalysis?: () => void;
      cleanupStagedApks?: () => void;
      getModulesJson?: () => string;
      openModule?: (idOrPackage: string) => boolean;
      installModule?: (idOrPackage: string) => boolean;
      openAnalysisEngine?: () => void;
    };
    onNativeUploadProgress?: (progress: NativeUploadProgress) => void;
    onNativeAnalysisSuccess?: (report: RiskReport) => void;
    onNativeAnalysisError?: (error: string) => void;
    __SPYAWARE_API_BASE__?: string;
  }
}
