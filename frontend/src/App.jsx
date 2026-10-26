import { useCallback, useEffect, useRef, useState } from "react";
import {
  ChevronRight,
  FileText,
  Landmark,
  Globe,
  Loader2,
  LockKeyhole,
  LogOut,
  Network,
  RefreshCw,
  Server,
  Shield,
  ShieldAlert,
} from "lucide-react";
import {
  apiGet,
  apiPost,
  apiPatch,
  TOKEN_KEY,
  Drawer,
  Field,
  Notice,
} from "./ConsoleUI";
import { FirewallWorkspace, IPSWorkspace } from "./NetworkModules";
import { WebFilterWorkspace, AccessWorkspace } from "./PolicyModules";
import { EDRWorkspace } from "./EDRWorkspace";
import "./console.css";

const modules = [
  {
    key: "firewall",
    title: "Firewall",
    subtitle: "Защитна стена",
    icon: Shield,
  },
  {
    key: "ips",
    title: "IPS",
    subtitle: "Откриване на прониквания",
    icon: ShieldAlert,
  },
  {
    key: "edr",
    title: "EDR",
    subtitle: "Сървъри и работни станции",
    icon: Server,
  },
  {
    key: "web_filter",
    title: "Web Filter",
    subtitle: "Интернет достъп",
    icon: Globe,
  },
  {
    key: "access",
    title: "IAM / MFA",
    subtitle: "Управление на достъпа",
    icon: LockKeyhole,
  },
];
const commonResources = [
  ["settings", "/module-settings/", true, "Настройки"],
  ["components", "/components/", true, "Компоненти"],
];
const resources = {
  firewall: [
    ["firewallStatus", "/firewall/status/", false, "Състояние на Firewall"],
    ["firewallRules", "/firewall/rules/", true, "Правила"],
    ["firewallEvents", "/firewall/events/", true, "Събития"],
  ],
  ips: [
    ["ipsStatus", "/ips/status/", false, "Състояние на IPS"],
    ["ipsEvents", "/ips/events/", true, "Събития"],
    ["ipsCategories", "/ips/rules/categories/", true, "Категории"],
    ["ipsCustomRules", "/ips/custom-rules/", true, "Потребителски правила"],
    ["ipsSettings", "/ips/settings/", false, "Настройки на IPS"],
  ],
  edr: [
    ["edrStatus", "/edr/status/", false, "Състояние на EDR"],
    ["edrEndpoints", "/edr/endpoints/", true, "Устройства"],
    ["edrEvents", "/edr/events/", true, "Събития"],
    ["edrThreats", "/edr/threats/", true, "Заплахи"],
    ["edrVulnerabilities", "/edr/vulnerabilities/", true, "Уязвимости"],
    ["edrSettings", "/edr/settings/", false, "Настройки на EDR"],
    ["crowdsecMetrics", "/edr/crowdsec/metrics/", false, "CrowdSec"],
  ],
  web_filter: [
    ["webRules", "/web-filter/rules/", true, "Уеб правила"],
    ["events", "/events/?component__category=web_filter", true, "Събития"],
  ],
  access: [
    ["accessRules", "/access/rules/", true, "Правила за достъп"],
    ["events", "/events/?component__category=access", true, "Събития"],
  ],
};
const initialData = {
  settings: [],
  components: [],
  firewallRules: [],
  firewallEvents: [],
  ipsEvents: [],
  ipsCategories: [],
  ipsCustomRules: [],
  edrEndpoints: [],
  edrEvents: [],
  edrThreats: [],
  edrVulnerabilities: [],
  webRules: [],
  accessRules: [],
  users: [],
  events: [],
};

async function getResource(path, list) {
  const payload = await apiGet(path);
  if (!list || Array.isArray(payload)) return payload;
  const rows = [...(payload.results || [])];
  let next = payload.next;
  const seen = new Set();
  while (next && !seen.has(next)) {
    seen.add(next);
    // Keep paginated requests on this API, including when running behind a proxy.
    const query = new URL(next, window.location.origin).search;
    const page = await apiGet(path.split("?")[0] + query);
    rows.push(...(page.results || []));
    next = page.next;
  }
  return rows;
}

function LoginPage({ onLogin }) {
  const [draft, setDraft] = useState({ username: "", password: "" });
  const [message, setMessage] = useState(null);
  const [busy, setBusy] = useState(false);
  const submit = async (event) => {
    event.preventDefault();
    setBusy(true);
    setMessage(null);
    try {
      const result = await apiPost("/auth/login/", draft);
      localStorage.setItem(TOKEN_KEY, result.token);
      onLogin(result.user);
    } catch (error) {
      setMessage({ tone: "danger", text: error.message });
    } finally {
      setBusy(false);
    }
  };
  return (
    <main className="login-page">
      <section className="login-panel">
        <div className="brand login-brand">
          <div className="brand-mark">
            <Network size={24} />
          </div>
          <div>
            <strong>SOC Control</strong>
            <span>Security Operations Center</span>
          </div>
        </div>
        <form className="login-form" onSubmit={submit}>
          <div className="eyebrow">ЗАЩИТЕН ДОСТЪП</div>
          <h1>Добре дошли</h1>
          <p>Влезте в конзолата за управление на сигурността.</p>
          <Notice message={message} />
          <Field label="Потребителско име">
            <input
              autoComplete="username"
              required
              value={draft.username}
              onChange={(event) =>
                setDraft({ ...draft, username: event.target.value })
              }
            />
          </Field>
          <Field label="Парола">
            <input
              type="password"
              autoComplete="current-password"
              required
              value={draft.password}
              onChange={(event) =>
                setDraft({ ...draft, password: event.target.value })
              }
            />
          </Field>
          <button className="primary" disabled={busy}>
            {busy ? (
              <Loader2 size={17} className="spin" />
            ) : (
              <LockKeyhole size={16} />
            )}
            Вход в конзолата
          </button>
        </form>
        <div className="login-footnote">
          NET Base 03.022 · Център за киберсигурност
        </div>
      </section>
    </main>
  );
}

export default function App() {
  const [activeView, setActiveView] = useState(() => {
    const saved = localStorage.getItem("soc_active_module");
    return modules.some((item) => item.key === saved) ? saved : "firewall";
  });
  const [user, setUser] = useState(null);
  const [booting, setBooting] = useState(true);
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState(initialData);
  const [loadedViews, setLoadedViews] = useState({});
  const [errors, setErrors] = useState([]);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [intervalSeconds, setIntervalSeconds] = useState(() => {
    const value = Number(localStorage.getItem("soc_refresh_interval"));
    return [30, 60].includes(value) ? value : 0;
  });
  const [infoModal, setInfoModal] = useState(null);
  const requestId = useRef(0);
  const dirty = useRef(new Set());
  const loadingRef = useRef(false);

  useEffect(() => {
    let active = true;
    if (!localStorage.getItem(TOKEN_KEY)) {
      setBooting(false);
      return;
    }
    apiGet("/auth/me/")
      .then((currentUser) => {
        if (active) setUser(currentUser);
      })
      .catch((error) => {
        if (error.status === 401) localStorage.removeItem(TOKEN_KEY);
      })
      .finally(() => {
        if (active) setBooting(false);
      });
    return () => {
      active = false;
    };
  }, []);
  useEffect(() => {
    const expired = () => {
      localStorage.removeItem(TOKEN_KEY);
      requestId.current++;
      setUser(null);
      setData(initialData);
      setLoadedViews({});
    };
    const dirtyChange = (event) => {
      if (event.detail.dirty) dirty.current.add(event.detail.key);
      else dirty.current.delete(event.detail.key);
    };
    window.addEventListener("soc:session-expired", expired);
    window.addEventListener("console-dirty", dirtyChange);
    return () => {
      window.removeEventListener("soc:session-expired", expired);
      window.removeEventListener("console-dirty", dirtyChange);
    };
  }, []);

  const loadData = useCallback(async () => {
    if (!user) return;
    const current = ++requestId.current;
    loadingRef.current = true;
    setLoading(true);
    const requested = [
      ...commonResources,
      ...resources[activeView],
      ...(activeView === "access" && user.is_staff
        ? [["users", "/auth/users/", true, "Потребители"]]
        : []),
    ];
    const results = await Promise.allSettled(
      requested.map(([, path, list]) => getResource(path, list)),
    );
    if (current !== requestId.current) return;
    const next = {};
    const failures = [];
    results.forEach((result, index) => {
      const [key, , , label] = requested[index];
      if (result.status === "fulfilled") next[key] = result.value;
      else failures.push(label + ": " + result.reason.message);
    });
    setData((previous) => ({ ...previous, ...next }));
    setErrors(failures);
    setLoadedViews((previous) => ({ ...previous, [activeView]: true }));
    setLastUpdated(
      failures.length === requested.length ? null : new Date().toISOString(),
    );
    loadingRef.current = false;
    setLoading(false);
  }, [activeView, user]);

  useEffect(() => {
    loadData();
    return () => {
      requestId.current++;
      loadingRef.current = false;
    };
  }, [loadData]);
  useEffect(() => {
    if (!user || !intervalSeconds) return;
    const interval = setInterval(() => {
      if (!document.hidden && !loadingRef.current && dirty.current.size === 0)
        loadData();
    }, intervalSeconds * 1000);
    return () => clearInterval(interval);
  }, [intervalSeconds, loadData, user]);

  const navigate = (key) => {
    if (key === activeView) return;
    if (
      dirty.current.size &&
      !window.confirm("Има незапазени промени. Да напусна ли текущия модул?")
    )
      return;
    dirty.current.clear();
    setErrors([]);
    setLastUpdated(null);
    setActiveView(key);
    localStorage.setItem("soc_active_module", key);
  };
  const logout = async () => {
    if (
      dirty.current.size &&
      !window.confirm("Има незапазени промени. Да изляза ли от конзолата?")
    )
      return;
    try {
      await apiPost("/auth/logout/", {});
    } catch {
      /* local sign-out stays available */
    }
    requestId.current++;
    localStorage.removeItem(TOKEN_KEY);
    dirty.current.clear();
    setUser(null);
    setData(initialData);
    setLoadedViews({});
  };
  const saveSetting = async (id, body) => {
    await apiPatch("/module-settings/" + id + "/", body);
    await loadData();
  };
  const actions = { reload: loadData, saveSetting, user };
  const selectedModule = modules.find((item) => item.key === activeView);
  const pages = {
    firewall: FirewallWorkspace,
    ips: IPSWorkspace,
    edr: EDRWorkspace,
    web_filter: WebFilterWorkspace,
    access: AccessWorkspace,
  };
  const Page = pages[activeView];
  if (booting)
    return (
      <div className="boot-screen">
        <Loader2 className="spin" size={25} />
        <span>Свързване с конзолата…</span>
      </div>
    );
  if (!user) return <LoginPage onLogin={setUser} />;

  return (
    <div className="app-shell console-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">
            <Network size={23} />
          </div>
          <div>
            <strong>SOC Control</strong>
            <span>Security Operations Center</span>
          </div>
          <div className="mobile-session">
            <button
              className="icon-button"
              aria-label="Лиценз NET Base 03.022 03-022-0134"
              onClick={() => setInfoModal("license")}
            >
              <FileText size={17} />
            </button>
            <button className="icon-button" aria-label="Изход" onClick={logout}>
              <LogOut size={17} />
            </button>
          </div>
        </div>
        <div className="sidebar-section-label">МОДУЛИ ЗА ЗАЩИТА</div>
        <nav aria-label="Модули за сигурност">
          {modules.map((module) => {
            const Icon = module.icon;
            return (
              <button
                key={module.key}
                className={activeView === module.key ? "active" : ""}
                onClick={() => navigate(module.key)}
                aria-current={activeView === module.key ? "page" : undefined}
                title={module.title + ": " + module.subtitle}
              >
                <Icon size={19} />
                <span>
                  <strong>{module.title}</strong>
                  <small>{module.subtitle}</small>
                </span>
                {activeView === module.key && (
                  <ChevronRight className="nav-chevron" size={15} />
                )}
              </button>
            );
          })}
        </nav>
        <div className="sidebar-system">
          <div>
            <span className="status-dot" />
            <strong>NET Base</strong>
            <span>03.022</span>
          </div>
          <p>Конзола за управление на сигурността</p>
        </div>
        <div className="sidebar-info-actions">
          <button onClick={() => setInfoModal("project")}>
            <Landmark size={16} />
            <span>Проект BG16RFPR001-1.012-0189-C01</span>
          </button>
          <button onClick={() => setInfoModal("license")}>
            <FileText size={16} />
            <span>Лиценз NET Base 03.022 03-022-0134</span>
          </button>
        </div>
        <div className="sidebar-user">
          <div className="user-avatar">
            {(user.full_name || user.username).slice(0, 2).toUpperCase()}
          </div>
          <div>
            <strong>{user.full_name || user.username}</strong>
            <span>{user.is_staff ? "Администратор" : "Оператор"}</span>
          </div>
          <button
            className="icon-button"
            title="Изход"
            aria-label="Изход"
            onClick={logout}
          >
            <LogOut size={17} />
          </button>
        </div>
      </aside>
      <main className="console-main">
        <header className="console-topbar">
          <div className="breadcrumb">
            Сигурност
            <ChevronRight size={13} />
            <strong>{selectedModule.title}</strong>
          </div>
          <div className="console-topbar-actions">
            <span className="sync-label">
              {loading
                ? "Обновяване…"
                : lastUpdated
                  ? "Обновено " +
                    new Date(lastUpdated).toLocaleTimeString("bg-BG", {
                      hour: "2-digit",
                      minute: "2-digit",
                    })
                  : "Очакване на данни"}
            </span>
            <select
              aria-label="Автоматично обновяване"
              value={intervalSeconds}
              onChange={(event) => {
                const value = Number(event.target.value);
                setIntervalSeconds(value);
                localStorage.setItem("soc_refresh_interval", value);
              }}
            >
              <option value="0">Ръчно обновяване</option>
              <option value="30">На всеки 30 сек.</option>
              <option value="60">На всеки 60 сек.</option>
            </select>
            <button className="secondary" disabled={loading} onClick={loadData}>
              <RefreshCw size={15} className={loading ? "spin" : ""} />
              Обнови
            </button>
          </div>
        </header>
        <div className="console-content">
          {errors.length > 0 && (
            <Notice
              message={{
                tone: "danger",
                text: "Някои данни не са обновени. " + errors.join(" · "),
              }}
            />
          )}
          {!loadedViews[activeView] ? (
            <div
              className="workspace-skeleton"
              aria-busy="true"
              aria-label="Зареждане на модула"
            >
              <div />
              <div />
              <div />
              <span>
                <Loader2 className="spin" size={20} />
                Зареждане на {selectedModule.title}…
              </span>
            </div>
          ) : (
            <Page key={activeView} data={data} actions={actions} />
          )}
        </div>
        <footer className="console-footer">
          <span>SOC Control · NET Base 03.022</span>
          <span>Пламели финанс ЕООД</span>
        </footer>
      </main>
      {infoModal && (
        <Drawer
          title={
            infoModal === "project"
              ? "Проект BG16RFPR001-1.012-0189-C01"
              : "Лиценз NET Base 03.022 03-022-0134"
          }
          onClose={() => setInfoModal(null)}
        >
          {infoModal === "project" ? (
            <img
              className="project-poster"
              src={
                (import.meta.env.BASE_URL || "/").replace(/\/$/, "") +
                "/Plakat-Plameli-Digi.jpg"
              }
              alt="Проект BG16RFPR001-1.012-0189-C01"
            />
          ) : (
            <dl className="detail-grid">
              {[
                ["Разработчик", "Ай-Ти Степ ООД"],
                ["Система за защита", "NET Base 03.022"],
                ["Лиценз", "03-022-0134"],
                ["Лицензополучател", "Пламели финанс ЕООД"],
                ["Финансирано по проект", "BG16RFPR001-1.012-0189-C01"],
              ].map(([label, value]) => (
                <div key={label}>
                  <dt>{label}</dt>
                  <dd>{value}</dd>
                </div>
              ))}
            </dl>
          )}
        </Drawer>
      )}
    </div>
  );
}
