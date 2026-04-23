// utils/complianceConfig.js
// Shared configuration and helpers for the multi-cloud Compliance dashboards

// ─── Framework registry ───────────────────────────────────────────────────────

export const COMPLIANCE_FRAMEWORKS = {
  dpdp: {
    key: "dpdp",
    label: "DPDP",
    fullName: "Digital Personal Data Protection Act, 2023",
    description:
      "India's Digital Personal Data Protection Act — governs how personal data is collected, stored, and processed.",
    simpleExplanation:
      "The DPDP Act is India's primary data-privacy law. It mandates that organisations handling personal data of Indian citizens implement appropriate security safeguards, obtain consent, and allow data principals to exercise their rights.",
    whoNeedsIt:
      "Any organisation that collects or processes personal data of individuals in India.",
    keyFocus: "Consent management, data minimisation, breach notification, cross-border transfers.",
    icon: "🇮🇳",
    reportType: "dpdp",
    clouds: ["aws"], // AWS-only framework
  },
};

// ─── Cloud account localStorage keys ──────────────────────────────────────────

export const CLOUD_ACCOUNT_KEYS = {
  aws: "account_details",
  azure: "azure_account_details",
  gcp: "gcp_account_details",
};

// ─── Severity helpers ─────────────────────────────────────────────────────────

const SEVERITY_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3, Passed: 4, Unknown: 5 };

export const sortBySeverity = (findings) =>
  [...findings].sort(
    (a, b) =>
      (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99),
  );

const normalizeSeverity = (value) => {
  if (!value || value === "None" || value === "none") return "Passed";
  return value;
};

// ─── Normalise raw results into a uniform finding shape ───────────────────────

export const normalizeFindings = (results = [], cloud = "aws") =>
  results.map((r) => ({
    id: r.control_id || r.id || "",
    check_name: r.check_name || r.title || "",
    service: r.service || "",
    severity: normalizeSeverity(r.severity_level || r.severity),
    severity_score: r.severity_score || 0,
    affected: r.additional_info?.affected ?? r.affected ?? 0,
    total_scanned: r.additional_info?.total_scanned ?? r.total_scanned ?? 0,
    region: r.region || "global",
    cloud,
    source: cloud,
    fullData: r,
  }));

// ─── Multi-cloud merge ────────────────────────────────────────────────────────

export const mergeMultiCloudFindings = (awsResult, azureResult, gcpResult) => {
  const clouds = { aws: awsResult, azure: azureResult, gcp: gcpResult };
  const findings = [];
  const cloudStatuses = {};

  for (const [cloud, result] of Object.entries(clouds)) {
    if (!result) {
      cloudStatuses[cloud] = { status: "skipped", lastScanned: null, error: null };
      continue;
    }
    cloudStatuses[cloud] = {
      status: result.status || "error",
      lastScanned: result.lastScanned || null,
      error: result.error || null,
    };
    if (Array.isArray(result.findings)) {
      findings.push(...result.findings);
    }
  }

  return { findings, cloudStatuses };
};

// ─── Cloud filter ─────────────────────────────────────────────────────────────

export const filterByCloud = (findings, cloud) => {
  if (!cloud || cloud === "all") return findings;
  return findings.filter((f) => f.cloud === cloud);
};
