import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

// Mirroring the pure logic of getModuleStatusBadge from frontend/src/App.tsx
function getModuleStatusCategory(rawStatus?: string | null): {
  label: string;
  category: 'Completed' | 'Failed' | 'Inconclusive' | 'Skipped';
  isSafeOrZeroRisk: boolean;
} {
  const status = (rawStatus || 'NOT_REQUESTED').toUpperCase();
  if (status === 'COMPLETED' || status === 'COMPLETED_CLEAN' || status === 'COMPLETED_WITH_FINDINGS' || status === 'NOT_ATTRIBUTED') {
    return {
      label: status === 'NOT_ATTRIBUTED' ? 'COMPLETED (NO TRAFFIC)' : 'COMPLETED',
      category: 'Completed',
      isSafeOrZeroRisk: false
    };
  }
  if (status === 'FAILED' || status === 'INSTALLATION_FAILED' || status === 'LAUNCH_FAILED' || status === 'CAPTURE_FAILED') {
    return {
      label: status.replace(/_/g, ' '),
      category: 'Failed',
      isSafeOrZeroRisk: false
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
      category: 'Inconclusive',
      isSafeOrZeroRisk: false
    };
  }
  return {
    label: 'SKIPPED',
    category: 'Skipped',
    isSafeOrZeroRisk: false
  };
}

// Logic for formatting dynamic / network module scores safely
function formatModuleScore(score: number | null | undefined): string {
  if (score === null || score === undefined) {
    return 'N/A';
  }
  return score.toFixed(1);
}

// Logic for computing progress bar style safely without false green / zero-risk indication
function getProgressBarConfig(score: number | null | undefined, defaultColorClass: string): { widthPercent: number; colorClass: string } {
  if (score === null || score === undefined) {
    return { widthPercent: 0, colorClass: 'bg-slate-200' };
  }
  return { widthPercent: Math.min(100, Math.max(0, score)), colorClass: defaultColorClass };
}

describe('Module Status Badging and Categorization', () => {
  it('correctly categorizes completed statuses', () => {
    assert.equal(getModuleStatusCategory('COMPLETED').category, 'Completed');
    assert.equal(getModuleStatusCategory('COMPLETED_CLEAN').category, 'Completed');
    assert.equal(getModuleStatusCategory('COMPLETED_WITH_FINDINGS').category, 'Completed');
    assert.equal(getModuleStatusCategory('NOT_ATTRIBUTED').category, 'Completed');
    assert.equal(getModuleStatusCategory('NOT_ATTRIBUTED').label, 'COMPLETED (NO TRAFFIC)');
  });

  it('correctly categorizes failed statuses', () => {
    assert.equal(getModuleStatusCategory('FAILED').category, 'Failed');
    assert.equal(getModuleStatusCategory('INSTALLATION_FAILED').category, 'Failed');
    assert.equal(getModuleStatusCategory('LAUNCH_FAILED').category, 'Failed');
    assert.equal(getModuleStatusCategory('CAPTURE_FAILED').category, 'Failed');
    assert.equal(getModuleStatusCategory('LAUNCH_FAILED').label, 'LAUNCH FAILED');
  });

  it('correctly categorizes inconclusive and unavailable statuses', () => {
    assert.equal(getModuleStatusCategory('INCOMPATIBLE_ABI').category, 'Inconclusive');
    assert.equal(getModuleStatusCategory('INCOMPATIBLE_ABI').label, 'UNAVAILABLE (INCOMPATIBLE ABI)');
    assert.equal(getModuleStatusCategory('UNAVAILABLE').category, 'Inconclusive');
    assert.equal(getModuleStatusCategory('INCONCLUSIVE').category, 'Inconclusive');
    assert.equal(getModuleStatusCategory('TIMEOUT').category, 'Inconclusive');
    assert.equal(getModuleStatusCategory('NO_LAUNCHABLE_ACTIVITY').category, 'Inconclusive');
    assert.equal(getModuleStatusCategory('EMULATOR_UNAVAILABLE').category, 'Inconclusive');
    assert.equal(getModuleStatusCategory('RUNTIME_UNAVAILABLE').category, 'Inconclusive');
  });

  it('correctly categorizes skipped or unrequested statuses', () => {
    assert.equal(getModuleStatusCategory('SKIPPED').category, 'Skipped');
    assert.equal(getModuleStatusCategory('NOT_REQUESTED').category, 'Skipped');
    assert.equal(getModuleStatusCategory(null).category, 'Skipped');
    assert.equal(getModuleStatusCategory(undefined).category, 'Skipped');
  });

  it('never marks an unavailable or failed module as zero-risk or safe', () => {
    const statuses = ['FAILED', 'INSTALLATION_FAILED', 'INCOMPATIBLE_ABI', 'UNAVAILABLE', 'TIMEOUT', null];
    for (const st of statuses) {
      const cat = getModuleStatusCategory(st);
      assert.equal(cat.isSafeOrZeroRisk, false, `Status ${st} must not imply zero risk or safe`);
    }
  });
});

describe('Score Formatting & Progress Bar Defense', () => {
  it('formats null and undefined scores as N/A instead of crashing or showing 0.0', () => {
    assert.equal(formatModuleScore(null), 'N/A');
    assert.equal(formatModuleScore(undefined), 'N/A');
    assert.equal(formatModuleScore(0), '0.0');
    assert.equal(formatModuleScore(42.5), '42.5');
  });

  it('renders a neutral muted progress bar with 0% width when score is null', () => {
    const dynamicConfig = getProgressBarConfig(null, 'bg-emerald-600');
    assert.equal(dynamicConfig.widthPercent, 0);
    assert.equal(dynamicConfig.colorClass, 'bg-slate-200');

    const networkConfig = getProgressBarConfig(null, 'bg-purple-600');
    assert.equal(networkConfig.widthPercent, 0);
    assert.equal(networkConfig.colorClass, 'bg-slate-200');

    const activeConfig = getProgressBarConfig(75.5, 'bg-purple-600');
    assert.equal(activeConfig.widthPercent, 75.5);
    assert.equal(activeConfig.colorClass, 'bg-purple-600');
  });
});
