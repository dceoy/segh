"use strict";

const MANAGED_DASHBOARD = /<!-- segh-dashboard: v1 -->/;
const REPOSITORY_ID = /<!-- segh-repository-id: ([0-9]+) -->/;

function retryable(error) {
  const status = error?.status || error?.response?.status;
  return status === 429 || (Number.isInteger(status) && status >= 500 && status <= 599) ||
    (status === 403 && /secondary rate limit|rate limit/i.test(String(error?.message || "")));
}

async function list(method, params) {
  const items = [];
  for (let page = 1; page <= 10; page += 1) {
    const response = await method({...params, per_page: 100, page});
    if (!Array.isArray(response?.data)) throw new Error("GitHub list API returned a malformed response");
    items.push(...response.data);
    if (response.data.length < 100) return items;
  }
  throw new Error("GitHub list API exceeded the 1000 item bound");
}

function managedDashboard(body) {
  return MANAGED_DASHBOARD.test(String(body || ""));
}

function repositoryId(body) {
  const match = String(body || "").match(REPOSITORY_ID);
  const id = match ? Number.parseInt(match[1], 10) : 0;
  return Number.isSafeInteger(id) && id > 0 ? id : null;
}

module.exports = {list, managedDashboard, repositoryId, retryable};
