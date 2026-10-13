import api from "./api";

export async function getRemediationActions() {
  const response = await api.get("/remediation/actions");
  return Array.isArray(response?.data?.actions) ? response.data.actions : [];
}

export async function getRemediationAction(actionId) {
  const response = await api.get(`/remediation/actions/${encodeURIComponent(actionId)}`);
  return response?.data?.action || null;
}

export async function createRemediationProposal(actionId, payload) {
  const response = await api.post(
    `/remediation/actions/${encodeURIComponent(actionId)}/proposals`,
    payload
  );
  return response.data;
}

export async function approveRemediation(remediationId) {
  const response = await api.patch(
    `/remediation/${encodeURIComponent(remediationId)}/approve`,
    { comment: "Approved from CloudGuardAI Remediation Center" }
  );
  return response.data;
}

export async function executeRemediation(remediationId) {
  const response = await api.post(
    `/remediation/${encodeURIComponent(remediationId)}/execute`,
    { confirmed: true }
  );
  return response.data;
}

export async function getRemediationAudit(remediationId) {
  const response = await api.get(
    `/audit/remediation/${encodeURIComponent(remediationId)}`
  );
  return Array.isArray(response?.data?.items) ? response.data.items : [];
}

export async function verifyRemediation(remediationId) {
  const response = await api.post(
    `/remediation/${encodeURIComponent(remediationId)}/verify`
  );
  return response.data;
}

export async function getRemediationSettings(accountId) {
  const response = await api.get(
    `/remediation/settings/${encodeURIComponent(accountId)}`
  );
  return response.data;
}

export async function updateRemediationSettings(accountId, serviceToggles) {
  const response = await api.put(
    `/remediation/settings/${encodeURIComponent(accountId)}`,
    serviceToggles
  );
  return response.data;
}

export async function createAIRemediationProposal(findingId) {
  const response = await api.post("/remediation/ai-proposals", {
    finding_id: findingId,
  });
  return response.data;
}
