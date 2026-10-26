import { test, expect } from "@playwright/test";

// Each browser runs against isolated API fixtures. No real rules or users are changed.
const date = "2026-10-26T08:30:00Z";
const user = {
  id: 1,
  username: "operator.test",
  full_name: "Security Admin",
  is_staff: true,
  is_active: true,
};
const setting = (key, id) => ({
  id,
  key,
  enabled: true,
  mode: "enforce",
  notes: "",
  updated_at: date,
  settings: {
    default_action: "allow",
    default_effect: "deny",
    log_allowed: true,
  },
});
const firewallRules = Array.from({ length: 14 }, (_, index) => ({
  id: index + 1,
  name:
    [
      "Административен достъп",
      "Публични уеб услуги",
      "Ограничаване на външен SSH",
      "Защита на вътрешна мрежа",
    ][index % 4] +
    " " +
    (index + 1),
  description: "Мрежова политика · инфраструктура",
  priority: (index + 1) * 10,
  enabled: index !== 3,
  action: index % 3 === 0 ? "block" : "allow",
  protocol: "tcp",
  direction: index % 2 ? "outbound" : "inbound",
  source_cidr: index % 2 ? "10.20.0.0/16" : "any",
  source_port: "any",
  destination_cidr: "10.30.0.0/16",
  destination_port: "443",
  hit_count: 123 + index,
  updated_at: date,
}));
const webRules = [
  {
    id: 1,
    name: "Блокиране на рискови домейни",
    enabled: true,
    priority: 10,
    pattern: "example.com",
    match_type: "domain",
    category: "Рискови домейни",
    action: "block",
    hit_count: 321,
    updated_at: date,
  },
  {
    id: 2,
    name: "Корпоративни приложения",
    enabled: true,
    priority: 20,
    pattern: "work.example.org",
    match_type: "domain",
    category: "Бизнес",
    action: "allow",
    hit_count: 158,
    updated_at: date,
  },
];
const accessRules = [
  {
    id: 1,
    name: "VPN с потвърдена MFA",
    enabled: true,
    priority: 10,
    network_type: "vpn",
    group: "employees",
    mfa_required: true,
    effect: "allow",
    hit_count: 452,
    updated_at: date,
  },
];
const endpoints = [
  {
    id: 1,
    hostname: "srv-sofia-01",
    ip: "10.20.0.11",
    os: "Ubuntu",
    os_version: "24.04",
    status: "online",
    security_status: "attention",
    agent_version: "4.9",
    threats_count: 1,
    vulnerabilities_count: 1,
    last_seen: date,
    first_seen: date,
  },
  {
    id: 2,
    hostname: "workstation-02",
    ip: "10.20.0.42",
    os: "Windows",
    os_version: "11",
    status: "offline",
    security_status: "protected",
    agent_version: "4.9",
    threats_count: 0,
    vulnerabilities_count: 0,
    last_seen: date,
  },
];
const events = [
  {
    id: 1,
    title: "Подозрителен процес",
    severity: "high",
    category: "suspicious_process",
    endpoint: 1,
    endpoint_hostname: "srv-sofia-01",
    source_ip: "203.0.113.8",
    process_name: "bash",
    timestamp: date,
    action: "alert",
    source: "wazuh",
    raw_event: { rule_id: "test-100" },
  },
];
const vulns = [
  {
    id: 1,
    endpoint: 1,
    endpoint_hostname: "srv-sofia-01",
    cve: "CVE-TEST-0001",
    package: "example-package",
    installed_version: "1.0",
    fixed_version: "1.1",
    severity: "high",
    status: "open",
  },
];

async function mockApi(page, { failed = null } = {}) {
  const writes = [];
  const data = {
    "/auth/me/": user,
    "/module-settings/": [
      setting("firewall", 1),
      setting("ips", 2),
      setting("edr", 3),
      setting("web_filter", 4),
      setting("access", 5),
    ],
    "/components/": [],
    "/firewall/status/": {
      enabled: true,
      backend: "nftables",
      runtime_available: true,
      active_rules: 13,
      blocked_24h: 127,
      last_rule_update: date,
      last_apply: date,
      has_unapplied_changes: false,
    },
    "/firewall/rules/": structuredClone(firewallRules),
    "/firewall/events/": [],
    "/ips/status/": {
      service_status: "available",
      installed: true,
      runtime_available: true,
      mode: "ids",
      rules_enabled: 1482,
      alerts_24h: 12,
      blocked_24h: 0,
      high_severity: 2,
      interfaces: ["eth0"],
      version: "7.0",
      last_event: date,
    },
    "/ips/events/": [
      {
        id: 1,
        signature: "ET SCAN Suspicious activity",
        severity: "high",
        source_ip: "203.0.113.2",
        destination_ip: "10.20.0.11",
        destination_port: 22,
        protocol: "TCP",
        category: "Scan",
        action: "alert",
        timestamp: date,
      },
    ],
    "/ips/rules/categories/": [
      { id: 1, name: "emerging-scan", rule_count: 420, enabled: true },
    ],
    "/ips/custom-rules/": [],
    "/ips/settings/": {
      ...setting("ips", 2),
      settings: {
        mode: "ids",
        interface: "eth0",
        home_net: "10.20.0.0/16",
        logging_enabled: true,
      },
    },
    "/edr/status/": {
      endpoints: 2,
      online: 1,
      offline: 1,
      threats_24h: 1,
      vulnerable_endpoints: 1,
      critical_24h: 0,
      high_24h: 1,
      never_connected: 0,
      last_event: date,
    },
    "/edr/endpoints/": endpoints,
    "/edr/events/": events,
    "/edr/threats/": [
      {
        id: 1,
        event: 1,
        title: events[0].title,
        endpoint_hostname: endpoints[0].hostname,
        severity: "high",
        category: "suspicious_process",
        status: "new",
        updated_at: date,
      },
    ],
    "/edr/vulnerabilities/": vulns,
    "/edr/settings/": {
      ...setting("edr", 3),
      settings: {
        manager_url: "https://wazuh.example.com:55000",
        agent_offline_timeout_minutes: 15,
      },
    },
    "/edr/crowdsec/metrics/": {
      ok: true,
      generated_at: date,
      sections: [
        {
          title: "Acquisition",
          columns: ["Source", "Lines read"],
          rows: [{ Source: "syslog", "Lines read": "1240" }],
        },
      ],
    },
    "/edr/endpoints/1/events/": events,
    "/edr/endpoints/1/vulnerabilities/": vulns,
    "/web-filter/rules/": structuredClone(webRules),
    "/access/rules/": accessRules,
    "/events/": [],
    "/auth/users/": [
      user,
      {
        id: 2,
        username: "analyst",
        full_name: "SOC Analyst",
        is_staff: false,
        is_active: true,
        email: "analyst@example.com",
      },
    ],
  };
  await page.addInitScript(() =>
    localStorage.setItem("soc_control_token", "isolated-test-token"),
  );
  await page.route("**/api/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname.replace(/^\/api/, "");
    if (path === failed)
      return route.fulfill({
        status: 503,
        json: { error: "Тестов източник недостъпен" },
      });
    if (request.method() === "GET")
      return route.fulfill({ json: data[path] ?? [] });
    const body = request.postDataJSON();
    writes.push({ path, method: request.method(), body });
    if (path === "/web-filter/evaluate/")
      return route.fulfill({
        json: {
          action: "block",
          policy_action: "block",
          mode: "enforce",
          module_enabled: true,
          reason: "matched_rule",
          matched_rule: webRules[0],
          category: "Рискови домейни",
        },
      });
    if (path === "/access/evaluate/")
      return route.fulfill({
        json: {
          effect: body.mfa_verified ? "allow" : "deny",
          policy_effect: body.mfa_verified ? "allow" : "deny",
          mode: "enforce",
          module_enabled: true,
          reason: "mfa_required",
          mfa_required: true,
          mfa_verified: body.mfa_verified,
          matched_rule: accessRules[0],
        },
      });
    if (request.method() === "POST" && path === "/web-filter/rules/") {
      const saved = { ...body, id: 10, updated_at: date };
      data[path].push(saved);
      return route.fulfill({ status: 201, json: saved });
    }
    if (request.method() === "PATCH" && path.startsWith("/module-settings/")) {
      const id = Number(path.split("/")[2]);
      const target = data["/module-settings/"].find((item) => item.id === id);
      Object.assign(target, body, { updated_at: "2026-10-26T09:00:00Z" });
      return route.fulfill({ json: target });
    }
    return route.fulfill({ json: { ...body, ok: true } });
  });
  return writes;
}

const nav = (page, name) =>
  page
    .getByRole("navigation", { name: "Модули за сигурност" })
    .getByRole("button", { name });

test("all modules and their tabs render with no runtime errors", async ({
  page,
}) => {
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await mockApi(page);
  await page.goto("/");
  for (const name of [/Firewall/, /^IPS/, /^EDR/, /Web Filter/, /IAM/]) {
    await nav(page, name).click();
    await expect(page.locator(".workspace-title h1")).toBeVisible();
    const tabs = page.getByRole("tab");
    const count = await tabs.count();
    for (let index = 0; index < count; index++) {
      await tabs.nth(index).click();
      await expect(tabs.nth(index)).toHaveAttribute("aria-selected", "true");
    }
    await tabs.first().click();
    await page.screenshot({
      path:
        "test-results/screenshots/" +
        String(name).replace(/[^a-zA-Z]/g, "") +
        ".png",
      fullPage: true,
    });
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= window.innerWidth,
      ),
    ).toBeTruthy();
  }
  expect(errors).toEqual([]);
});

test("firewall search, pagination and export operate on filtered data", async ({
  page,
}) => {
  await mockApi(page);
  await page.goto("/");
  await expect(page.locator("tbody tr")).toHaveCount(10);
  await page.getByRole("button", { name: "Следваща страница" }).click();
  await expect(page.locator("tbody tr")).toHaveCount(4);
  await page
    .getByRole("textbox", { name: "Търси име, IP адрес или описание…" })
    .fill("външен SSH");
  await expect(page.locator("tbody tr")).toHaveCount(3);
  const downloaded = page.waitForEvent("download");
  await page.getByRole("button", { name: "Експорт" }).click();
  expect((await downloaded).suggestedFilename()).toBe("firewall-rules.csv");
});

test("web rule creation and simulation use the right API contracts", async ({
  page,
}) => {
  const writes = await mockApi(page);
  await page.goto("/");
  await nav(page, /Web Filter/).click();
  await page.getByRole("button", { name: "Ново правило", exact: true }).click();
  await page
    .getByRole("dialog")
    .getByLabel("Име на правилото")
    .fill("Test policy");
  await page
    .getByRole("dialog")
    .getByRole("textbox", { name: "Домейн", exact: true })
    .fill("test.example.net");
  await page
    .getByRole("button", { name: "Създай правило", exact: true })
    .click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(page.getByText("Test policy", { exact: true })).toBeVisible();
  await page.getByRole("tab", { name: "Провери сайт" }).click();
  await page
    .getByLabel("URL адрес", { exact: true })
    .fill("https://example.com/path");
  await page.getByRole("button", { name: "Изпълни проверка" }).click();
  await expect(page.getByText("Ефективно решение")).toBeVisible();
  expect(
    writes.some(
      (write) =>
        write.path === "/web-filter/rules/" &&
        write.body.pattern === "test.example.net",
    ),
  ).toBeTruthy();
  expect(writes.at(-1).path).toBe("/web-filter/evaluate/");
});

test("unsaved settings survive tab changes and block module navigation", async ({
  page,
}) => {
  await mockApi(page);
  await page.goto("/");
  await page.getByRole("tab", { name: "Настройки" }).click();
  await page.getByLabel("Бележка").fill("Pending change");
  await page.getByRole("tab", { name: "Правила", exact: false }).click();
  await page.getByRole("tab", { name: "Настройки" }).click();
  await expect(page.getByLabel("Бележка")).toHaveValue("Pending change");
  page.once("dialog", (dialog) => dialog.dismiss());
  await nav(page, /^IPS/).click();
  await expect(page.locator(".workspace-title h1")).toHaveText("Защитна стена");
  await page.getByRole("button", { name: "Запази настройките" }).click();
  await expect(
    page.getByRole("button", { name: "Запази настройките" }),
  ).toBeDisabled();
});

test("partial API failure leaves the working module usable", async ({
  page,
}) => {
  await mockApi(page, { failed: "/firewall/events/" });
  await page.goto("/");
  await expect(page.getByRole("alert")).toContainText(
    "Тестов източник недостъпен",
  );
  await expect(page.locator("tbody tr")).toHaveCount(10);
  await expect(
    page.getByRole("button", { name: "Ново правило" }),
  ).toBeEnabled();
});

test("EDR endpoint drilldown opens scoped events and vulnerabilities", async ({
  page,
}) => {
  await mockApi(page);
  await page.goto("/");
  await nav(page, /^EDR/).click();
  await page.getByRole("tab", { name: "Устройства" }).click();
  await page.getByRole("button", { name: /srv-sofia-01/ }).click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "Време", exact: true })
    .click();
  await page
    .getByRole("dialog")
    .getByRole("tab", { name: "Уязвимости" })
    .click();
  await expect(
    page.getByRole("dialog").getByText("CVE-TEST-0001"),
  ).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
});

test("mobile layout preserves module names and confines table overflow", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await mockApi(page);
  await page.goto("/");
  await expect(page.locator(".workspace-title h1")).toBeVisible();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBeTruthy();
  await nav(page, /IAM/).click();
  await expect(
    page.getByRole("tab", { name: "Правила за достъп" }),
  ).toBeVisible();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBeTruthy();
  await page.screenshot({
    path: "test-results/screenshots/mobile.png",
    fullPage: true,
  });
});

test("IAM simulation sends MFA context without recording an access event", async ({
  page,
}) => {
  const writes = await mockApi(page);
  await page.goto("/");
  await nav(page, /IAM/).click();
  await page.getByRole("tab", { name: "Провери достъп" }).click();
  await page.getByLabel("Потребител", { exact: true }).fill("analyst");
  await page.getByLabel("Група", { exact: true }).fill("employees");
  await page.getByLabel("MFA е потвърдена").check();
  await page.getByRole("button", { name: "Изпълни проверка" }).click();
  await expect(page.getByText("Ефективно решение")).toBeVisible();
  expect(writes.at(-1)).toMatchObject({
    path: "/access/evaluate/",
    body: {
      username: "analyst",
      group: "employees",
      network_type: "vpn",
      mfa_verified: true,
    },
  });
});

test("EDR settings save a validated numeric offline threshold", async ({
  page,
}) => {
  const writes = await mockApi(page);
  await page.goto("/");
  await nav(page, /^EDR/).click();
  await page.getByRole("tab", { name: "Настройки" }).click();
  await page.getByLabel("Праг за офлайн агент, минути").fill("30");
  await page.getByRole("button", { name: "Запази", exact: true }).click();
  await expect(page.getByText("Настройките на EDR са запазени.")).toBeVisible();
  expect(writes.at(-1)).toMatchObject({
    path: "/edr/settings/",
    method: "PUT",
    body: { agent_offline_timeout_minutes: 30 },
  });
});

test("IPS signature SID must match before an API write", async ({ page }) => {
  const writes = await mockApi(page);
  await page.goto("/");
  await nav(page, /^IPS/).click();
  await page.getByRole("tab", { name: "Сигнатури" }).click();
  await page.getByRole("button", { name: "Нова сигнатура" }).click();
  await page.getByLabel("Име на правилото").fill("SSH detection");
  await page.getByLabel("Идентификатор на сигнатурата (SID)").fill("1000009");
  await page.getByRole("button", { name: "Запази правило" }).click();
  await expect(page.getByRole("alert")).toContainText(
    "SID в сигнатурата трябва да съвпада",
  );
  expect(writes).toHaveLength(0);
});

test("nested discard confirmation keeps editor data when cancelled", async ({
  page,
}) => {
  await mockApi(page);
  await page.goto("/");
  await page.getByRole("button", { name: "Ново правило" }).click();
  await page.getByLabel("Име на правилото").fill("Unsaved rule");
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(2);
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(1);
  await expect(page.getByLabel("Име на правилото")).toHaveValue("Unsaved rule");
});

test("validation errors stay in the rule editor", async ({ page }) => {
  await mockApi(page);
  await page.route("**/api/web-filter/rules/", async (route) =>
    route.request().method() === "POST"
      ? route.fulfill({
          status: 400,
          json: { pattern: ["Тестова грешка в домейна"] },
        })
      : route.fallback(),
  );
  await page.goto("/");
  await nav(page, /Web Filter/).click();
  await page.getByRole("button", { name: "Ново правило", exact: true }).click();
  await page.getByLabel("Име на правилото").fill("Rejected rule");
  await page
    .getByRole("textbox", { name: "Домейн", exact: true })
    .fill("test.example.net");
  await page
    .getByRole("button", { name: "Създай правило", exact: true })
    .click();
  await expect(page.getByRole("dialog").getByRole("alert")).toContainText(
    "Тестова грешка в домейна",
  );
  await expect(page.getByLabel("Име на правилото")).toHaveValue(
    "Rejected rule",
  );
});
