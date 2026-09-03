import { useEffect, useState } from "react";
import {
  Activity,
  ArrowDown,
  ArrowUp,
  AlertTriangle,
  FileText,
  Filter,
  Globe,
  Landmark,
  LockKeyhole,
  Network,
  Pencil,
  Plus,
  RefreshCw,
  Save,
  Server,
  Shield,
  ShieldAlert,
  Trash2,
  X,
} from "lucide-react";

const APP_BASE_PATH = import.meta.env.BASE_URL || "/";
const APP_BASE_PREFIX = APP_BASE_PATH === "/" ? "" : APP_BASE_PATH.replace(/\/$/, "");
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || `${APP_BASE_PREFIX}/api`;
const AUTH_TOKEN_KEY = "soc_control_token";

function publicAssetUrl(path) {
  return `${APP_BASE_PREFIX}${path.startsWith("/") ? path : `/${path}`}`;
}

function getAuthToken() {
  return localStorage.getItem(AUTH_TOKEN_KEY);
}

const modules = [
  { key: "firewall", title: "Firewall: защитна стена", short: "Firewall", icon: Shield },
  { key: "ips", title: "IPS: откриване на прониквания", short: "IPS", icon: ShieldAlert },
  { key: "edr", title: "EDR: сървъри и работни станции", short: "EDR", icon: Server },
  { key: "web_filter", title: "Web Filter: интернет достъп", short: "Web", icon: Globe },
  { key: "access", title: "IAM/MFA: управление на достъпа", short: "MFA", icon: LockKeyhole },
];

const statusText = {
  healthy: "Нормално",
  warning: "Внимание",
  critical: "Критично",
  offline: "Няма връзка",
};

const severityText = {
  informational: "Инфо",
  low: "Ниска",
  medium: "Средна",
  high: "Висока",
  critical: "Критична",
};

const decisionText = {
  allow: "Разреши",
  block: "Блокирай",
  drop: "Блокирай",
  blocked: "Блокирано",
  reject: "Отхвърли",
  log: "Запиши в журнал",
  review: "За преглед",
  deny: "Забрани",
  alert: "Създай сигнал",
};

const agentStatusText = {
  online: "Онлайн",
  offline: "Офлайн",
  never_connected: "Не е свързван",
  error: "Грешка",
};

const endpointSecurityText = {
  protected: "Защитен",
  attention: "Внимание",
  at_risk: "В риск",
  critical: "Критично",
};

const threatStatusText = {
  new: "Нова",
  investigating: "Разследва се",
  resolved: "Решена",
  ignored: "Игнорирана",
  blocked: "Блокирана",
};

const settingFields = {
  firewall: [
    {
      key: "default_action",
      label: "Ако няма съвпадащо правило",
      type: "select",
      defaultValue: "allow",
      options: [
        ["allow", "Разрешавай"],
        ["block", "Блокирай"],
        ["log", "Само записвай"],
      ],
    },
    { key: "log_allowed", label: "Записвай разрешените връзки", type: "checkbox", defaultValue: true },
  ],
  ips: [
    { key: "inspect_payloads", label: "Проверявай съдържанието на заявките", type: "checkbox", defaultValue: true },
    { key: "block_on_critical", label: "Блокирай критични атаки", type: "checkbox", defaultValue: true },
  ],
  edr: [
    { key: "auto_quarantine", label: "Предлагай карантина автоматично", type: "checkbox", defaultValue: true },
    { key: "telemetry_retention_days", label: "Съхранявай телеметрия, дни", type: "number", defaultValue: 30 },
  ],
  web_filter: [
    {
      key: "default_action",
      label: "Ако сайтът не е в правилата",
      type: "select",
      defaultValue: "allow",
      options: [
        ["allow", "Разрешавай"],
        ["block", "Блокирай"],
        ["review", "Изпращай за преглед"],
      ],
    },
    { key: "log_allowed", label: "Записвай разрешените посещения", type: "checkbox", defaultValue: false },
  ],
  access: [
    {
      key: "default_effect",
      label: "Ако няма правило за достъп",
      type: "select",
      defaultValue: "deny",
      options: [
        ["allow", "Разрешавай"],
        ["deny", "Забранявай"],
        ["review", "Изпращай за преглед"],
      ],
    },
    { key: "mfa_grace_minutes", label: "Отсрочка за MFA, минути", type: "number", defaultValue: 0 },
  ],
};

function normalizeList(payload) {
  return Array.isArray(payload) ? payload : payload?.results || [];
}

async function apiRequest(path, options = {}) {
  const token = getAuthToken();
  const response = await fetch(`${API_BASE_URL}${path}`, {
    headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Token ${token}` } : {}), ...(options.headers || {}) },
    ...options,
  });
  if (!response.ok) {
    let details = "";
    try {
      const payload = await response.json();
      details = payload.error || payload.message || Object.values(payload).flat().join(" ");
    } catch {
      details = "";
    }
    if (response.status === 401) localStorage.removeItem(AUTH_TOKEN_KEY);
    throw new Error(details || `Действието не може да бъде изпълнено. Код: ${response.status}`);
  }
  if (response.status === 204) return null;
  return response.json();
}

const apiGet = (path) => apiRequest(path);
const apiPost = (path, body) => apiRequest(path, { method: "POST", body: JSON.stringify(body) });
const apiPatch = (path, body) => apiRequest(path, { method: "PATCH", body: JSON.stringify(body) });
const apiDelete = (path) => apiRequest(path, { method: "DELETE" });

function formatNumber(value) {
  return new Intl.NumberFormat("bg-BG").format(value || 0);
}

function formatDate(value) {
  if (!value) return "няма данни";
  return new Intl.DateTimeFormat("bg-BG", {
    day: "2-digit",
    month: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value));
}

function moduleTitle(key) {
  return modules.find((module) => module.key === key)?.title || key;
}

function Field({ label, children }) {
  return (
    <label className="field">
      <span>{label}</span>
      {children}
    </label>
  );
}

function TextInput({ value, onChange, placeholder, type = "text" }) {
  return <input type={type} value={value} onChange={(event) => onChange(event.target.value)} placeholder={placeholder} />;
}

function SelectInput({ value, onChange, children }) {
  return <select value={value} onChange={(event) => onChange(event.target.value)}>{children}</select>;
}

function Pill({ value, type = "status" }) {
  const label = type === "severity" ? severityText[value] || value : statusText[value] || decisionText[value] || value;
  return <span className={`pill ${type}-${value}`}>{label}</span>;
}

function Kpi({ icon: Icon, label, value, tone }) {
  return (
    <div className={`kpi ${tone || ""}`}>
      <div className="kpi-icon">
        <Icon size={20} />
      </div>
      <div>
        <span>{label}</span>
        <strong>{formatNumber(value)}</strong>
      </div>
    </div>
  );
}

function LoginPage({ onLogin }) {
  const [draft, setDraft] = useState({ username: "", password: "" });
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (event) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const result = await apiRequest("/auth/login/", { method: "POST", body: JSON.stringify(draft) });
      localStorage.setItem(AUTH_TOKEN_KEY, result.token);
      onLogin(result.user);
    } catch (currentError) {
      setError(currentError.message);
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
            <span>Платформа за защита</span>
          </div>
        </div>
        <form onSubmit={submit} className="login-form">
          <div>
            <h1>Вход</h1>
            <p>Въведете потребителско име и парола, за да управлявате политиките за сигурност.</p>
          </div>
          {error && <div className="notice danger">{error}</div>}
          <Field label="Потребител">
            <TextInput value={draft.username} onChange={(value) => setDraft((current) => ({ ...current, username: value }))} placeholder="admin" />
          </Field>
          <Field label="Парола">
            <TextInput type="password" value={draft.password} onChange={(value) => setDraft((current) => ({ ...current, password: value }))} placeholder="••••••••" />
          </Field>
          <button className="primary" type="submit" disabled={busy || !draft.username || !draft.password}>
            <LockKeyhole size={16} />
            <span>{busy ? "Влизане..." : "Влез"}</span>
          </button>
        </form>
      </section>
    </main>
  );
}

function ModuleSettings({ setting, component, moduleKey, onSave }) {
  const [draft, setDraft] = useState({ enabled: true, mode: "monitor", notes: "", settings: {} });

  useEffect(() => {
    const defaults = {};
    for (const field of settingFields[moduleKey] || []) {
      defaults[field.key] = field.defaultValue;
    }
    setDraft({
      enabled: true,
      mode: setting?.mode || "monitor",
      notes: setting?.notes || "",
      settings: { ...defaults, ...(setting?.settings || {}) },
    });
  }, [moduleKey, setting?.id, setting?.updated_at]);

  const updateSetting = (key, value) => {
    setDraft((current) => ({ ...current, settings: { ...current.settings, [key]: value } }));
  };

  const save = async () => {
    if (!setting?.id) return;
    await onSave(setting.id, { ...draft, enabled: true });
  };

  return (
    <section className="panel settings-panel">
      <div className="panel-heading">
        <div>
          <h2>{moduleTitle(moduleKey)}</h2>
          <span>{component?.description}</span>
        </div>
        <span className="plain-status">Винаги включено</span>
      </div>
      <div className="settings-grid">
        <Field label="Режим на работа">
          <SelectInput value={draft.mode} onChange={(value) => setDraft((current) => ({ ...current, mode: value }))}>
            <option value="monitor">Само наблюдение</option>
            <option value="enforce">Прилагай защита</option>
            <option value="disabled">Изключен режим</option>
          </SelectInput>
        </Field>
        <Field label="Коментар">
          <TextInput value={draft.notes} onChange={(value) => setDraft((current) => ({ ...current, notes: value }))} placeholder="Например: собственик или среда" />
        </Field>
        {(settingFields[moduleKey] || []).map((field) =>
          field.type === "checkbox" ? (
            <label className="check-row" key={field.key}>
              <input type="checkbox" checked={Boolean(draft.settings[field.key])} onChange={(event) => updateSetting(field.key, event.target.checked)} />
              <span>{field.label}</span>
            </label>
          ) : (
            <Field key={field.key} label={field.label}>
              {field.type === "select" ? (
                <SelectInput value={draft.settings[field.key] ?? field.defaultValue} onChange={(value) => updateSetting(field.key, value)}>
                  {field.options.map(([value, label]) => (
                    <option key={value} value={value}>
                      {label}
                    </option>
                  ))}
                </SelectInput>
              ) : (
                <TextInput type="number" value={draft.settings[field.key] ?? field.defaultValue} onChange={(value) => updateSetting(field.key, Number(value))} />
              )}
            </Field>
          ),
        )}
      </div>
      <div className="panel-actions">
        <button className="primary" onClick={save}>
          <Save size={16} />
          <span>Запази настройките</span>
        </button>
      </div>
    </section>
  );
}

function EmptyState({ label }) {
  return <div className="empty-state">{label}</div>;
}

function RuleCards({ rows, endpoint, onRefresh, onEdit, fields, emptyLabel, showHits = true }) {
  const remove = async (row) => {
    await apiDelete(`${endpoint}/${row.id}/`);
    onRefresh();
  };

  return (
    <div className="cards-grid">
      {rows.map((row) => (
        <article className="rule-card" key={row.id}>
          <div className="rule-head">
            <div>
              <h3>{row.name}</h3>
              {showHits && <span>Съвпадения: {formatNumber(row.hit_count)}</span>}
            </div>
            <span className="plain-status">Включено</span>
          </div>
          <div className="rule-details">
            {fields.map((field) => (
              <div key={field.key}>
                <span>{field.label}</span>
                <strong>{field.render ? field.render(row) : row[field.key]}</strong>
              </div>
            ))}
          </div>
          <div className="card-actions">
            {onEdit && (
              <button className="secondary" onClick={() => onEdit(row)}>
                <Pencil size={15} />
              <span>Редактирай</span>
              </button>
            )}
            <button className="secondary danger" onClick={() => remove(row)}>
              <Trash2 size={15} />
              <span>Изтрий</span>
            </button>
          </div>
        </article>
      ))}
      {rows.length === 0 && <EmptyState label={emptyLabel || "Все още няма записи"} />}
    </div>
  );
}

function FormActions({ editing, onCancel, disabled }) {
  return (
    <div className="form-actions">
      {editing && (
        <button type="button" className="secondary" onClick={onCancel}>
          <X size={15} />
          <span>Отказ</span>
        </button>
      )}
      <button type="submit" className="primary" disabled={disabled}>
        {editing ? <Save size={16} /> : <Plus size={16} />}
        <span>{editing ? "Запази" : "Добави"}</span>
      </button>
    </div>
  );
}

function FriendlyResult({ result, kind }) {
  if (!result) return null;

  let tone = "ok";
  let title = "Готово";
  let details = [];

  if (kind === "firewall" || kind === "web") {
    const action = result.action;
    tone = ["block", "reject", "deny"].includes(action) ? "danger" : action === "review" ? "warn" : "ok";
    title = `Решение: ${decisionText[action] || action}`;
    details = [
      result.matched_rule ? `Правило: ${result.matched_rule.name}` : "Няма съвпадащо правило",
      result.category ? `Категория: ${result.category}` : "",
    ].filter(Boolean);
  } else if (kind === "ips") {
    tone = result.action === "block" ? "danger" : result.matches?.length ? "warn" : "ok";
    title = result.matches?.length ? `Намерени съвпадения: ${result.matches.length}` : "Не са открити атаки";
    details = [`Действие: ${decisionText[result.action] || result.action}`, `Риск: ${severityText[result.severity] || result.severity}`];
  } else if (kind === "edr") {
    tone = result.suspicious ? "danger" : "ok";
    title = result.suspicious ? "Подозрителна активност" : "Активът е приет";
    details = [result.asset?.name ? `Устройство: ${result.asset.name}` : "", result.asset?.edr_status ? `Статус: ${result.asset.edr_status}` : ""].filter(Boolean);
  } else if (kind === "access") {
    tone = result.effect === "deny" ? "danger" : result.effect === "review" ? "warn" : "ok";
    title = `Достъп: ${decisionText[result.effect] || result.effect}`;
    details = [`MFA се изисква: ${result.mfa_required ? "да" : "не"}`, `MFA премината: ${result.mfa_verified ? "да" : "не"}`];
  } else if (kind === "siem") {
    const alerts = result.correlation_alerts?.length || 0;
    tone = alerts ? "warn" : "ok";
    title = alerts ? `Създадени сигнали: ${alerts}` : "Журналът е приет";
    details = [result.event?.event_type ? `Събитие: ${result.event.event_type}` : "", result.event?.severity ? `Риск: ${severityText[result.event.severity]}` : ""].filter(Boolean);
  }

  return (
    <div className={`friendly-result ${tone}`}>
      <strong>{title}</strong>
      {details.map((detail) => (
        <span key={detail}>{detail}</span>
      ))}
    </div>
  );
}

function ProbePanel({ title, buttonLabel = "Провери", onRun, result, kind, disabled = false, children }) {
  return (
    <section className="panel probe">
      <div className="panel-heading">
        <h2>{title}</h2>
      </div>
      <div className="form-grid">{children}</div>
      <div className="panel-actions">
        <button className="primary" onClick={onRun} disabled={disabled}>
          <Activity size={16} />
          <span>{buttonLabel}</span>
        </button>
      </div>
      <FriendlyResult result={result} kind={kind} />
    </section>
  );
}

function ModuleSelect({ value, onChange }) {
  return (
    <SelectInput value={value} onChange={onChange}>
      {modules.map((module) => (
        <option key={module.key} value={module.key}>
          {module.title}
        </option>
      ))}
    </SelectInput>
  );
}

function ModuleLayout({ moduleKey, data, actions, children }) {
  const setting = data.settings.find((item) => item.key === moduleKey);
  const component = data.components.find((item) => item.category === moduleKey || item.key === moduleKey);
  return (
    <div className="module-layout">
      <ModuleSettings setting={setting} component={component} moduleKey={moduleKey} onSave={actions.saveSetting} />
      {children}
    </div>
  );
}

function FirewallPageV2({ data, actions }) {
  const blank = {
    name: "",
    enabled: true,
    priority: (data.firewallRules.length + 1) * 10,
    action: "block",
    direction: "inbound",
    protocol: "tcp",
    source_cidr: "any",
    source_port: "any",
    destination_cidr: "any",
    destination_port: "",
    description: "",
  };
  const [rule, setRule] = useState(blank);
  const [editingId, setEditingId] = useState(null);
  const [showForm, setShowForm] = useState(false);
  const [activeTab, setActiveTab] = useState("rules");
  const [message, setMessage] = useState(null);

  const status = data.firewallStatus || {};
  const rules = [...data.firewallRules].sort((a, b) => (a.priority || 0) - (b.priority || 0) || a.id - b.id);
  const events = data.firewallEvents || [];

  const setField = (key, value) => setRule((current) => ({ ...current, [key]: value }));

  const saveRule = async (event) => {
    event.preventDefault();
    setMessage(null);
    try {
      const payload = { ...rule, enabled: true, priority: Number(rule.priority) || 100 };
      if (editingId) await apiPatch(`/firewall/rules/${editingId}/`, payload);
      else await apiPost("/firewall/rules/", payload);
      setRule({ ...blank, priority: (rules.length + 2) * 10 });
      setEditingId(null);
      setShowForm(false);
      setMessage({ tone: "ok", text: "Правилото е запазено в базата данни. За да влезе в nftables, натиснете „Приложи правилата“." });
      actions.reload();
    } catch (error) {
      setMessage({ tone: "danger", text: error.message });
    }
  };

  const editRule = (row) => {
    setRule({ ...blank, ...row, source_port: row.source_port || "any" });
    setEditingId(row.id);
    setShowForm(true);
    setActiveTab("rules");
  };

  const applyRules = async (confirmAdminLockout = false) => {
    setMessage(null);
    try {
      const result = await apiPost("/firewall/apply/", { confirm_admin_lockout: confirmAdminLockout });
      if (result.warning && !confirmAdminLockout) {
        const approved = window.confirm(`${result.warning}. Да продължа ли с прилагането на правилата?`);
        if (approved) return applyRules(true);
      }
      setMessage({ tone: result.ok ? "ok" : "danger", text: result.message || result.error });
      actions.reload();
    } catch (error) {
      setMessage({ tone: "danger", text: error.message });
    }
  };

  return (
    <ModuleLayout moduleKey="firewall" data={data} actions={actions}>
      <section className="panel firewall-console">
        <div className="firewall-topbar">
          <div>
            <h2>Firewall: защитна стена</h2>
            <p>Филтриране на интернет трафик през nftables. Правилата се пазят в базата данни и се прилагат с отделна команда.</p>
          </div>
          <span className="plain-status">Винаги включено</span>
        </div>

        <div className="firewall-status-grid">
          <div><span>Firewall</span><strong>Включен</strong></div>
          <div><span>Backend</span><strong>{status.backend || "nftables"}</strong></div>
          <div><span>Активни правила</span><strong>{formatNumber(status.active_rules)}</strong></div>
          <div><span>Блокировки за 24 часа</span><strong>{formatNumber(status.blocked_24h)}</strong></div>
          <div><span>Последна промяна</span><strong>{formatDate(status.last_rule_update)}</strong></div>
          <div><span>Последно прилагане</span><strong>{formatDate(status.last_apply)}</strong></div>
        </div>

        {status.has_unapplied_changes && <div className="notice warn">Има неприложени промени</div>}
        {message && <div className={`notice ${message.tone}`}>{message.text}</div>}

        <div className="firewall-actions">
          <button className="secondary" type="button" onClick={() => { setShowForm((value) => !value); setEditingId(null); setRule(blank); }}>
            <Plus size={16} />
            <span>Добави правило</span>
          </button>
          <button className="primary" type="button" onClick={() => applyRules(false)}>
            <Save size={16} />
            <span>Приложи правилата</span>
          </button>
        </div>
      </section>

      {showForm && (
        <section className="panel">
          <div className="panel-heading">
            <h2>{editingId ? "Промяна на правило" : "Ново правило"}</h2>
          </div>
          <form className="form-grid firewall-form" onSubmit={saveRule}>
            <Field label="Име">
              <TextInput value={rule.name} onChange={(value) => setField("name", value)} placeholder="Например: Allow SSH from LAN" />
            </Field>
            <Field label="Посока">
              <SelectInput value={rule.direction} onChange={(value) => setField("direction", value)}>
                <option value="inbound">Входящо</option>
                <option value="outbound">Изходящо</option>
              </SelectInput>
            </Field>
            <Field label="Протокол">
              <SelectInput value={rule.protocol} onChange={(value) => setField("protocol", value)}>
                <option value="any">Any</option>
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
                <option value="icmp">ICMP</option>
              </SelectInput>
            </Field>
            <Field label="IP източник">
              <TextInput value={rule.source_cidr} onChange={(value) => setField("source_cidr", value)} placeholder="Any, 192.168.1.10 или 192.168.1.0/24" />
            </Field>
            <Field label="Порт източник">
              <TextInput value={rule.source_port} onChange={(value) => setField("source_port", value)} placeholder="Any или 443" />
            </Field>
            <Field label="IP дестинация">
              <TextInput value={rule.destination_cidr} onChange={(value) => setField("destination_cidr", value)} placeholder="Any, IP или CIDR" />
            </Field>
            <Field label="Порт дестинация">
              <TextInput value={rule.destination_port} onChange={(value) => setField("destination_port", value)} placeholder="22, 80, 443 или Any" />
            </Field>
            <Field label="Действие">
              <SelectInput value={rule.action} onChange={(value) => setField("action", value)}>
                <option value="allow">Разреши</option>
                <option value="block">Блокирай</option>
              </SelectInput>
            </Field>
            <Field label="Приоритет">
              <TextInput type="number" value={rule.priority} onChange={(value) => setField("priority", value)} />
            </Field>
            <Field label="Коментар">
              <TextInput value={rule.description} onChange={(value) => setField("description", value)} placeholder="Например: Administration" />
            </Field>
            <FormActions editing={Boolean(editingId)} disabled={!rule.name} onCancel={() => { setRule(blank); setEditingId(null); setShowForm(false); }} />
          </form>
        </section>
      )}

      <section className="panel wide">
        <div className="tabs">
          <button className={activeTab === "rules" ? "active" : ""} onClick={() => setActiveTab("rules")}>Правила</button>
          <button className={activeTab === "events" ? "active" : ""} onClick={() => setActiveTab("events")}>Събития</button>
        </div>
        {activeTab === "rules" ? (
          <FirewallRulesTable rows={rules} onRefresh={actions.reload} onEdit={editRule} />
        ) : (
          <FirewallEventsTable rows={events} />
        )}
      </section>
    </ModuleLayout>
  );
}

function FirewallRulesTable({ rows, onRefresh, onEdit }) {
  const remove = async (row) => {
    await apiDelete(`/firewall/rules/${row.id}/`);
    onRefresh();
  };
  const move = async (row, direction) => {
    await apiPost(`/firewall/rules/${row.id}/${direction === "up" ? "move-up" : "move-down"}/`, {});
    onRefresh();
  };

  if (!rows.length) return <EmptyState label="Все още няма правила. Добавете първото правило за филтриране." />;

  return (
    <div className="data-table firewall-table">
      <div className="table-row table-head">
        <span>Статус</span><span>Име</span><span>Посока</span><span>Протокол</span><span>Източник</span><span>Порт източник</span><span>Дестинация</span><span>Порт дестинация</span><span>Действие</span><span>Коментар</span><span>Операции</span>
      </div>
      {rows.map((row, index) => (
        <div className="table-row" key={row.id}>
          <span className="plain-status">Включено</span>
          <strong>{row.name}</strong>
          <span>{row.direction === "inbound" ? "Входящо" : row.direction === "outbound" ? "Изходящо" : "Any"}</span>
          <span>{(row.protocol || "any").toUpperCase()}</span>
          <span>{row.source_cidr || "Any"}</span>
          <span>{row.source_port || "Any"}</span>
          <span>{row.destination_cidr || "Any"}</span>
          <span>{row.destination_port || "Any"}</span>
          <span><Pill value={row.action} /></span>
          <span>{row.description || "-"}</span>
          <span className="row-actions">
            <button className="icon-button" onClick={() => move(row, "up")} disabled={index === 0} title="Нагоре"><ArrowUp size={15} /></button>
            <button className="icon-button" onClick={() => move(row, "down")} disabled={index === rows.length - 1} title="Надолу"><ArrowDown size={15} /></button>
            <button className="icon-button" onClick={() => onEdit(row)} title="Редактирай"><Pencil size={15} /></button>
            <button className="icon-button danger" onClick={() => remove(row)} title="Изтрий"><Trash2 size={15} /></button>
          </span>
        </div>
      ))}
    </div>
  );
}

function FirewallEventsTable({ rows }) {
  if (!rows.length) return <EmptyState label="Все още няма блокирани връзки." />;
  return (
    <div className="data-table firewall-events-table">
      <div className="table-row table-head">
        <span>Време</span><span>Източник</span><span>Дестинация</span><span>Порт източник</span><span>Порт дестинация</span><span>Протокол</span><span>Посока</span><span>Правило</span><span>Действие</span>
      </div>
      {rows.map((row) => {
        const details = row.extra_data || {};
        return (
          <div className="table-row" key={row.id}>
            <span>{formatDate(row.occurred_at)}</span>
            <span>{row.source_ip}</span>
            <span>{row.destination || details.destination_ip || "-"}</span>
            <span>{details.source_port || "Any"}</span>
            <span>{details.destination_port || "Any"}</span>
            <span>{(details.protocol || "any").toUpperCase()}</span>
            <span>{details.direction || "Any"}</span>
            <span>{details.matched_rule_name || "-"}</span>
            <span><Pill value={details.action || "block"} /></span>
          </div>
        );
      })}
    </div>
  );
}

function FirewallPage({ data, actions }) {
  const blank = {
    name: "",
    priority: 100,
    action: "block",
    direction: "any",
    protocol: "tcp",
    source_cidr: "any",
    destination_cidr: "any",
    destination_port: "443",
    description: "",
  };
  const [rule, setRule] = useState(blank);
  const [editingId, setEditingId] = useState(null);
  const [probe, setProbe] = useState({ source_ip: "", destination_ip: "", destination_port: "", protocol: "tcp", direction: "outbound" });
  const [result, setResult] = useState(null);

  const saveRule = async (event) => {
    event.preventDefault();
    if (editingId) await apiPatch(`/firewall/rules/${editingId}/`, rule);
    else await apiPost("/firewall/rules/", rule);
    setRule(blank);
    setEditingId(null);
    actions.reload();
  };

  return (
    <ModuleLayout moduleKey="firewall" data={data} actions={actions}>
      <section className="panel">
        <div className="panel-heading">
          <h2>{editingId ? "Изменить правило" : "Новое правило"}</h2>
        </div>
        <form className="form-grid firewall-form" onSubmit={saveRule}>
          <Field label="Название">
            <TextInput value={rule.name} onChange={(value) => setRule((current) => ({ ...current, name: value }))} placeholder="Например: запрет внешнего SSH" />
          </Field>
          <Field label="Действие">
            <SelectInput value={rule.action} onChange={(value) => setRule((current) => ({ ...current, action: value }))}>
              <option value="allow">Разрешить</option>
              <option value="block">Блокировать</option>
              <option value="reject">Отклонить</option>
              <option value="log">Записать в журнал</option>
            </SelectInput>
          </Field>
          <Field label="Направление">
            <SelectInput value={rule.direction} onChange={(value) => setRule((current) => ({ ...current, direction: value }))}>
              <option value="any">Любое</option>
              <option value="inbound">Входящее</option>
              <option value="outbound">Исходящее</option>
            </SelectInput>
          </Field>
          <Field label="Протокол">
            <SelectInput value={rule.protocol} onChange={(value) => setRule((current) => ({ ...current, protocol: value }))}>
              <option value="any">Любой</option>
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
              <option value="icmp">ICMP</option>
            </SelectInput>
          </Field>
          <Field label="Откуда">
            <TextInput value={rule.source_cidr} onChange={(value) => setRule((current) => ({ ...current, source_cidr: value }))} placeholder="any или 10.0.0.0/8" />
          </Field>
          <Field label="Куда">
            <TextInput value={rule.destination_cidr} onChange={(value) => setRule((current) => ({ ...current, destination_cidr: value }))} placeholder="any или 192.168.1.0/24" />
          </Field>
          <Field label="Порт">
            <TextInput value={rule.destination_port} onChange={(value) => setRule((current) => ({ ...current, destination_port: value }))} placeholder="443 или any" />
          </Field>
          <Field label="Приоритет">
            <TextInput type="number" value={rule.priority} onChange={(value) => setRule((current) => ({ ...current, priority: Number(value) }))} />
          </Field>
          <FormActions editing={Boolean(editingId)} disabled={!rule.name} onCancel={() => { setRule(blank); setEditingId(null); }} />
        </form>
      </section>

      <ProbePanel title="Проверить соединение" kind="firewall" result={result} disabled={!probe.source_ip || !probe.destination_ip || !probe.destination_port} onRun={async () => setResult(await apiPost("/firewall/evaluate/", { ...probe, destination: probe.destination_ip }))}>
        <Field label="IP источника">
          <TextInput value={probe.source_ip} onChange={(value) => setProbe((current) => ({ ...current, source_ip: value }))} placeholder="Например: 10.0.0.10" />
        </Field>
        <Field label="IP назначения">
          <TextInput value={probe.destination_ip} onChange={(value) => setProbe((current) => ({ ...current, destination_ip: value }))} placeholder="Например: 1.1.1.1" />
        </Field>
        <Field label="Порт">
          <TextInput value={probe.destination_port} onChange={(value) => setProbe((current) => ({ ...current, destination_port: value }))} placeholder="Например: 443" />
        </Field>
        <Field label="Протокол">
          <SelectInput value={probe.protocol} onChange={(value) => setProbe((current) => ({ ...current, protocol: value }))}>
            <option value="tcp">TCP</option>
            <option value="udp">UDP</option>
            <option value="icmp">ICMP</option>
          </SelectInput>
        </Field>
        <Field label="Направление">
          <SelectInput value={probe.direction} onChange={(value) => setProbe((current) => ({ ...current, direction: value }))}>
            <option value="outbound">Исходящее</option>
            <option value="inbound">Входящее</option>
          </SelectInput>
        </Field>
      </ProbePanel>

      <section className="panel wide">
        <div className="panel-heading">
          <h2>Правила</h2>
          <span>{data.firewallRules.length}</span>
        </div>
        <RuleCards
          rows={data.firewallRules}
          endpoint="/firewall/rules"
          onRefresh={actions.reload}
          onEdit={(row) => { setRule(row); setEditingId(row.id); }}
          emptyLabel="Правил пока нет. Добавьте первое правило фильтрации."
          fields={[
            { key: "action", label: "Действие", render: (row) => <Pill value={row.action} /> },
            { key: "direction", label: "Направление" },
            { key: "protocol", label: "Протокол" },
            { key: "source_cidr", label: "Откуда" },
            { key: "destination_cidr", label: "Куда" },
            { key: "destination_port", label: "Порт" },
          ]}
        />
      </section>
    </ModuleLayout>
  );
}

function IPSPage({ data, actions }) {
  const blank = { name: "", priority: 100, match_field: "payload", pattern: "", action: "alert", severity: "high", description: "" };
  const [rule, setRule] = useState(blank);
  const [editingId, setEditingId] = useState(null);
  const [probe, setProbe] = useState({ source_ip: "", destination: "", payload: "", url: "", message: "" });
  const [result, setResult] = useState(null);

  const saveRule = async (event) => {
    event.preventDefault();
    if (editingId) await apiPatch(`/ips/rules/${editingId}/`, rule);
    else await apiPost("/ips/rules/", rule);
    setRule(blank);
    setEditingId(null);
    actions.reload();
  };

  return (
    <ModuleLayout moduleKey="ips" data={data} actions={actions}>
      <section className="panel">
        <div className="panel-heading">
          <h2>{editingId ? "Изменить сигнатуру" : "Новая сигнатура"}</h2>
        </div>
        <form className="form-grid" onSubmit={saveRule}>
          <Field label="Название">
            <TextInput value={rule.name} onChange={(value) => setRule((current) => ({ ...current, name: value }))} placeholder="Например: SQL-инъекция" />
          </Field>
          <Field label="Где искать">
            <SelectInput value={rule.match_field} onChange={(value) => setRule((current) => ({ ...current, match_field: value }))}>
              <option value="payload">В запросе</option>
              <option value="url">В адресе сайта</option>
              <option value="message">В сообщении</option>
            </SelectInput>
          </Field>
          <Field label="Что искать">
            <TextInput value={rule.pattern} onChange={(value) => setRule((current) => ({ ...current, pattern: value }))} placeholder="Например: union select" />
          </Field>
          <Field label="Действие">
            <SelectInput value={rule.action} onChange={(value) => setRule((current) => ({ ...current, action: value }))}>
              <option value="alert">Создать алерт</option>
              <option value="block">Блокировать</option>
            </SelectInput>
          </Field>
          <Field label="Риск">
            <SelectInput value={rule.severity} onChange={(value) => setRule((current) => ({ ...current, severity: value }))}>
              <option value="medium">Средний</option>
              <option value="high">Высокий</option>
              <option value="critical">Критичный</option>
            </SelectInput>
          </Field>
          <FormActions editing={Boolean(editingId)} disabled={!rule.name || !rule.pattern} onCancel={() => { setRule(blank); setEditingId(null); }} />
        </form>
      </section>

      <ProbePanel title="Проверить сетевой запрос" kind="ips" result={result} disabled={!probe.payload && !probe.url && !probe.message} onRun={async () => setResult(await apiPost("/ips/evaluate/", probe))}>
        <Field label="IP источника">
          <TextInput value={probe.source_ip} onChange={(value) => setProbe((current) => ({ ...current, source_ip: value }))} placeholder="Например: 10.0.0.20" />
        </Field>
        <Field label="Назначение">
          <TextInput value={probe.destination} onChange={(value) => setProbe((current) => ({ ...current, destination: value }))} placeholder="Сервер или сервис" />
        </Field>
        <Field label="Адрес сайта">
          <TextInput value={probe.url} onChange={(value) => setProbe((current) => ({ ...current, url: value }))} placeholder="https://example.com" />
        </Field>
        <Field label="Содержимое запроса">
          <textarea value={probe.payload} onChange={(event) => setProbe((current) => ({ ...current, payload: event.target.value }))} rows={3} placeholder="Текст запроса или полезная нагрузка" />
        </Field>
      </ProbePanel>

      <section className="panel wide">
        <div className="panel-heading">
          <h2>Сигнатуры</h2>
          <span>{data.ipsRules.length}</span>
        </div>
        <RuleCards
          rows={data.ipsRules}
          endpoint="/ips/rules"
          onRefresh={actions.reload}
          onEdit={(row) => { setRule(row); setEditingId(row.id); }}
          emptyLabel="Сигнатур пока нет. Добавьте правило обнаружения."
          fields={[
            { key: "match_field", label: "Где искать" },
            { key: "pattern", label: "Что искать" },
            { key: "action", label: "Действие", render: (row) => <Pill value={row.action} /> },
            { key: "severity", label: "Риск", render: (row) => <Pill value={row.severity} type="severity" /> },
          ]}
        />
      </section>
    </ModuleLayout>
  );
}

function IPSPageV2({ data, actions }) {
  const status = data.ipsStatus || {};
  const settings = data.ipsSettings?.settings || {};
  const [tab, setTab] = useState("overview");
  const [message, setMessage] = useState(null);
  const [filters, setFilters] = useState({ severity: "", source_ip: "", destination_ip: "", protocol: "", category: "", action: "", search: "" });
  const [selected, setSelected] = useState(null);
  const [draft, setDraft] = useState({
    enabled: data.ipsSettings?.enabled ?? true,
    mode: settings.mode || "ids",
    interface: settings.interface || "",
    home_net: settings.home_net || "192.168.1.0/24",
    auto_update: Boolean(settings.auto_update),
    update_period: settings.update_period || "daily",
    logging_enabled: settings.logging_enabled ?? true,
  });
  const [customRule, setCustomRule] = useState({ name: "", sid: 1000001, raw_rule: "alert tcp any any -> $HOME_NET 22 (msg:\"Possible SSH connection\"; sid:1000001; rev:1;)", enabled: true });

  useEffect(() => {
    const current = data.ipsSettings?.settings || {};
    setDraft({
      enabled: data.ipsSettings?.enabled ?? true,
      mode: current.mode || "ids",
      interface: current.interface || "",
      home_net: current.home_net || "192.168.1.0/24",
      auto_update: Boolean(current.auto_update),
      update_period: current.update_period || "daily",
      logging_enabled: current.logging_enabled ?? true,
    });
  }, [data.ipsSettings?.id, data.ipsSettings?.updated_at]);

  const runAction = async (path, body = {}, okText = "Готово") => {
    setMessage(null);
    try {
      const result = await apiPost(path, body);
      setMessage({ tone: "ok", text: result.message || okText });
      actions.reload();
    } catch (error) {
      setMessage({ tone: "danger", text: error.message });
    }
  };

  const saveSettings = async () => {
    if (draft.mode === "ips" && !window.confirm("IPS може да блокира мрежови връзки. Некоректни правила могат да доведат до загуба на достъп до услуги.")) return;
    setMessage(null);
    try {
      await apiRequest("/ips/settings/", { method: "PUT", body: JSON.stringify(draft) });
      setMessage({ tone: "ok", text: "Настройките на IPS са запазени" });
      actions.reload();
    } catch (error) {
      setMessage({ tone: "danger", text: error.message });
    }
  };

  const saveCustomRule = async (event) => {
    event.preventDefault();
    setMessage(null);
    try {
      const result = await apiPost("/ips/custom-rules/", { ...customRule, enabled: true });
      setMessage({ tone: result.validation_error ? "warn" : "ok", text: result.validation_error || "Потребителското правило е запазено" });
      setCustomRule({ ...customRule, sid: Number(customRule.sid) + 1, name: "" });
      actions.reload();
    } catch (error) {
      setMessage({ tone: "danger", text: error.message });
    }
  };

  const filteredEvents = (data.ipsEvents || []).filter((event) => {
    return Object.entries(filters).every(([key, value]) => {
      if (!value) return true;
      const source = key === "search" ? event.signature : event[key];
      return String(source || "").toLowerCase().includes(value.toLowerCase());
    });
  });

  const blockSource = async (event) => {
    await runAction(`/ips/events/${event.id}/block-source/`, {}, "Firewall правило за IP източника е създадено");
  };

  return (
    <ModuleLayout moduleKey="ips" data={data} actions={actions}>
      <section className="panel firewall-console">
        <div className="firewall-topbar">
          <div>
            <h2>IPS: откриване на прониквания</h2>
            <p>Suricata IDS/IPS: приемане на EVE JSON събития, управление на режим, правила и оперативни действия.</p>
          </div>
          <span className="plain-status">Винаги включено</span>
        </div>
        <div className="firewall-status-grid">
          <div><span>IPS</span><strong>Включен</strong></div>
          <div><span>Engine</span><strong>Suricata</strong></div>
          <div><span>Режим</span><strong>{(status.mode || "ids").toUpperCase()}</strong></div>
          <div><span>Правила</span><strong>{formatNumber(status.rules_enabled)}</strong></div>
          <div><span>Заплахи за 24 часа</span><strong>{formatNumber(status.alerts_24h)}</strong></div>
          <div><span>Suricata</span><strong>{status.service_status || "unknown"}</strong></div>
        </div>
        {message && <div className={`notice ${message.tone}`}>{message.text}</div>}
        <div className="firewall-actions">
          <button className="secondary" onClick={() => actions.reload()}><RefreshCw size={16} /><span>Обнови</span></button>
          <button className="secondary" onClick={() => runAction("/ips/update-rules/", {}, "Обновяването на правилата е стартирано")}><RefreshCw size={16} /><span>Обнови правила</span></button>
          <button className="primary" onClick={() => runAction("/ips/apply/", draft, "Настройките са приложени")}><Save size={16} /><span>Приложи настройките</span></button>
        </div>
      </section>

      <section className="panel wide">
        <div className="tabs">
          {["overview", "events", "rules", "settings"].map((item) => (
            <button key={item} className={tab === item ? "active" : ""} onClick={() => setTab(item)}>
              {item === "overview" ? "Преглед" : item === "events" ? "Събития" : item === "rules" ? "Правила" : "Настройки"}
            </button>
          ))}
        </div>

        {tab === "overview" && (
          <>
            <div className="firewall-status-grid">
              <div><span>Блокирани за 24 ч</span><strong>{formatNumber(status.blocked_24h)}</strong></div>
              <div><span>Висок риск</span><strong>{formatNumber(status.high_severity)}</strong></div>
              <div><span>Последно събитие</span><strong>{formatDate(status.last_event)}</strong></div>
              <div><span>Интерфейс</span><strong>{settings.interface || "не е избран"}</strong></div>
              <div><span>HOME_NET</span><strong>{settings.home_net || "не е зададен"}</strong></div>
              <div><span>Версия</span><strong>{status.version || "няма данни"}</strong></div>
            </div>
            <IPSEventsTable rows={(data.ipsEvents || []).slice(0, 5)} onSelect={setSelected} compact />
          </>
        )}

        {tab === "events" && (
          <>
            <div className="form-grid compact-filters">
              <Field label="Важност"><SelectInput value={filters.severity} onChange={(value) => setFilters((c) => ({ ...c, severity: value }))}><option value="">Всички</option><option value="informational">Инфо</option><option value="low">Ниска</option><option value="medium">Средна</option><option value="high">Висока</option><option value="critical">Критична</option></SelectInput></Field>
              <Field label="IP източник"><TextInput value={filters.source_ip} onChange={(value) => setFilters((c) => ({ ...c, source_ip: value }))} /></Field>
              <Field label="IP дестинация"><TextInput value={filters.destination_ip} onChange={(value) => setFilters((c) => ({ ...c, destination_ip: value }))} /></Field>
              <Field label="Протокол"><TextInput value={filters.protocol} onChange={(value) => setFilters((c) => ({ ...c, protocol: value }))} /></Field>
              <Field label="Категория"><TextInput value={filters.category} onChange={(value) => setFilters((c) => ({ ...c, category: value }))} /></Field>
              <Field label="Действие"><TextInput value={filters.action} onChange={(value) => setFilters((c) => ({ ...c, action: value }))} /></Field>
              <Field label="Сигнатура"><TextInput value={filters.search} onChange={(value) => setFilters((c) => ({ ...c, search: value }))} /></Field>
            </div>
            <IPSEventsTable rows={filteredEvents} onSelect={setSelected} />
          </>
        )}

        {tab === "rules" && (
          <>
            <div className="data-table ips-category-table">
              <div className="table-row table-head"><span>Категория</span><span>Правила</span><span>Статус</span><span>Операции</span></div>
              {(data.ipsCategories || []).map((category) => (
                <div className="table-row" key={category.id}>
                  <strong>{category.name}</strong>
                  <span>{formatNumber(category.rule_count)}</span>
                  <span>Включено</span>
                  <span className="plain-status">Активно</span>
                </div>
              ))}
            </div>
            <form className="form-grid ips-custom-form" onSubmit={saveCustomRule}>
              <Field label="Име"><TextInput value={customRule.name} onChange={(value) => setCustomRule((c) => ({ ...c, name: value }))} placeholder="Possible SSH connection" /></Field>
              <Field label="SID"><TextInput type="number" value={customRule.sid} onChange={(value) => setCustomRule((c) => ({ ...c, sid: Number(value) }))} /></Field>
              <Field label="Сигнатура Suricata"><textarea value={customRule.raw_rule} onChange={(event) => setCustomRule((c) => ({ ...c, raw_rule: event.target.value }))} rows={3} /></Field>
              <FormActions disabled={!customRule.name || !customRule.raw_rule} />
            </form>
            <IPSCustomRulesTable rows={data.ipsCustomRules || []} onRefresh={actions.reload} />
          </>
        )}

        {tab === "settings" && (
          <div className="settings-grid">
            <Field label="Режим"><SelectInput value={draft.mode} onChange={(value) => setDraft((c) => ({ ...c, mode: value }))}><option value="ids">Само откриване (IDS)</option><option value="ips">Откриване и блокиране (IPS)</option></SelectInput></Field>
            <Field label="Интерфейс"><SelectInput value={draft.interface} onChange={(value) => setDraft((c) => ({ ...c, interface: value }))}><option value="">Авто</option>{(status.interfaces || data.ipsSettings?.interfaces || []).map((name) => <option key={name} value={name}>{name}</option>)}</SelectInput></Field>
            <Field label="HOME_NET"><TextInput value={draft.home_net} onChange={(value) => setDraft((c) => ({ ...c, home_net: value }))} placeholder="192.168.1.0/24,10.0.0.0/8" /></Field>
            <Field label="Период на обновяване"><SelectInput value={draft.update_period} onChange={(value) => setDraft((c) => ({ ...c, update_period: value }))}><option value="daily">Всеки ден</option><option value="weekly">Всяка седмица</option></SelectInput></Field>
            <label className="check-row"><input type="checkbox" checked={draft.auto_update} onChange={(event) => setDraft((c) => ({ ...c, auto_update: event.target.checked }))} /><span>Автоматично обновяване на правила</span></label>
            <label className="check-row"><input type="checkbox" checked={draft.logging_enabled} onChange={(event) => setDraft((c) => ({ ...c, logging_enabled: event.target.checked }))} /><span>Записвай събитията</span></label>
            <div className="panel-actions"><button className="primary" onClick={saveSettings}><Save size={16} /><span>Запази настройките</span></button></div>
          </div>
        )}
      </section>

      {selected && <IPSEventDetails event={selected} onClose={() => setSelected(null)} onBlock={blockSource} />}
    </ModuleLayout>
  );
}

function IPSEventsTable({ rows, onSelect, compact = false }) {
  if (!rows.length) return <EmptyState label="Все още няма IPS събития. Те ще се появят след приемане на Suricata EVE JSON." />;
  return (
    <div className="data-table ips-events-table">
      {!compact && <div className="table-row table-head"><span>Време</span><span>Важност</span><span>Сигнатура</span><span>Категория</span><span>Източник</span><span>Дестинация</span><span>Протокол</span><span>Действие</span><span>Интерфейс</span></div>}
      {rows.map((row) => (
        <button className="table-row table-button" key={row.id} onClick={() => onSelect(row)}>
          <span>{formatDate(row.timestamp)}</span>
          <span><Pill value={row.severity} type="severity" /></span>
          <strong>{row.signature}</strong>
          <span>{row.category || "-"}</span>
          <span>{row.source_ip}:{row.source_port || "*"}</span>
          <span>{row.destination_ip}:{row.destination_port || "*"}</span>
          <span>{(row.protocol || "").toUpperCase() || "-"}</span>
          <span>{row.action}</span>
          <span>{row.interface || "-"}</span>
        </button>
      ))}
    </div>
  );
}

function IPSEventDetails({ event, onClose, onBlock }) {
  return (
    <section className="panel wide detail-panel">
      <div className="panel-heading">
        <div><h2>{event.signature}</h2><span>SID {event.signature_id || "-"} · Flow {event.flow_id || "-"}</span></div>
        <button className="secondary" onClick={onClose}><X size={15} /><span>Затвори</span></button>
      </div>
      <div className="firewall-status-grid">
        <div><span>Дата</span><strong>{formatDate(event.timestamp)}</strong></div>
        <div><span>Важност</span><strong>{event.severity}</strong></div>
        <div><span>Категория</span><strong>{event.category || "-"}</strong></div>
        <div><span>Източник</span><strong>{event.source_ip}:{event.source_port || "*"}</strong></div>
        <div><span>Дестинация</span><strong>{event.destination_ip}:{event.destination_port || "*"}</strong></div>
        <div><span>Действие</span><strong>{event.action}</strong></div>
      </div>
      <div className="firewall-actions">
        <button className="primary" onClick={() => onBlock(event)}><Shield size={16} /><span>Блокирай IP</span></button>
      </div>
      <details className="technical-details">
        <summary>Технически данни</summary>
        <pre>{JSON.stringify(event.raw_event || {}, null, 2)}</pre>
      </details>
    </section>
  );
}

function IPSCustomRulesTable({ rows, onRefresh }) {
  if (!rows.length) return <EmptyState label="Все още няма потребителски правила." />;
  return (
    <div className="data-table ips-custom-table">
      <div className="table-row table-head"><span>SID</span><span>Име</span><span>Статус</span><span>Проверка</span><span>Операции</span></div>
      {rows.map((row) => (
        <div className="table-row" key={row.id}>
          <strong>{row.sid}</strong>
          <span>{row.name}</span>
          <span>Включено</span>
          <span>{row.validation_error || "OK"}</span>
          <span className="row-actions">
            <button className="icon-button danger" onClick={async () => { await apiDelete(`/ips/custom-rules/${row.id}/`); onRefresh(); }}><Trash2 size={15} /></button>
          </span>
        </div>
      ))}
    </div>
  );
}

function EDRPageV2({ data, actions }) {
  const status = data.edrStatus || {};
  const settings = data.edrSettings?.settings || {};
  const [tab, setTab] = useState("overview");
  const [selectedEndpoint, setSelectedEndpoint] = useState(null);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [message, setMessage] = useState(null);
  const [filters, setFilters] = useState({ severity: "", category: "", endpoint: "", source_ip: "", search: "" });
  const [draft, setDraft] = useState({
    enabled: data.edrSettings?.enabled ?? true,
    manager_url: settings.manager_url || "http://localhost:55000",
    agent_offline_timeout_minutes: settings.agent_offline_timeout_minutes || 15,
    event_retention_days: settings.event_retention_days || 90,
    automatic_refresh: settings.automatic_refresh ?? true,
  });

  useEffect(() => {
    const current = data.edrSettings?.settings || {};
    setDraft({
      enabled: data.edrSettings?.enabled ?? true,
      manager_url: current.manager_url || "http://localhost:55000",
      agent_offline_timeout_minutes: current.agent_offline_timeout_minutes || 15,
      event_retention_days: current.event_retention_days || 90,
      automatic_refresh: current.automatic_refresh ?? true,
    });
  }, [data.edrSettings?.id, data.edrSettings?.updated_at]);

  const saveSettings = async () => {
    setMessage(null);
    try {
      await apiRequest("/edr/settings/", { method: "PUT", body: JSON.stringify({ ...draft, enabled: true }) });
      setMessage({ tone: "ok", text: "Настройките на EDR са запазени" });
      actions.reload();
    } catch (error) {
      setMessage({ tone: "danger", text: error.message });
    }
  };

  const install = async (platform) => {
    setMessage(null);
    try {
      const result = await apiGet(`/edr/install/${platform}/`);
      setMessage({ tone: "ok", text: result.command });
    } catch (error) {
      setMessage({ tone: "danger", text: error.message });
    }
  };

  const blockEventIp = async (event) => {
    setMessage(null);
    try {
      await apiPost(`/edr/events/${event.id}/block-ip/`, {});
      setMessage({ tone: "ok", text: "Firewall правило за IP от EDR събитие е създадено" });
      actions.reload();
    } catch (error) {
      setMessage({ tone: "danger", text: error.message });
    }
  };

  const filteredEvents = (data.edrEvents || []).filter((event) =>
    Object.entries(filters).every(([key, value]) => {
      if (!value) return true;
      const source = key === "endpoint" ? event.endpoint_hostname : key === "search" ? `${event.title} ${event.description}` : event[key];
      return String(source || "").toLowerCase().includes(value.toLowerCase());
    }),
  );

  return (
    <ModuleLayout moduleKey="edr" data={data} actions={actions}>
      <section className="panel firewall-console">
        <div className="firewall-topbar">
          <div>
            <h2>EDR</h2>
            <p>Централизирано състояние на Wazuh endpoints, събития за сигурност, заплахи и уязвимости.</p>
          </div>
          <span className="plain-status">Винаги включено</span>
        </div>
        <div className="firewall-status-grid">
          <div><span>EDR</span><strong>Включен</strong></div>
          <div><span>Доставчик</span><strong>{status.provider || "wazuh"}</strong></div>
          <div><span>Устройства</span><strong>{formatNumber(status.endpoints)}</strong></div>
          <div><span>Онлайн</span><strong>{formatNumber(status.online)}</strong></div>
          <div><span>Офлайн</span><strong>{formatNumber(status.offline)}</strong></div>
          <div><span>Заплахи за 24 ч</span><strong>{formatNumber(status.threats_24h)}</strong></div>
        </div>
        {message && <div className={`notice ${message.tone}`}>{message.text}</div>}
        <div className="firewall-actions">
          <button className="secondary" onClick={() => actions.reload()}><RefreshCw size={16} /><span>Обнови</span></button>
          <button className="secondary" onClick={() => install("linux")}><Plus size={16} /><span>Добави Linux</span></button>
          <button className="secondary" onClick={() => install("windows")}><Plus size={16} /><span>Добави Windows</span></button>
        </div>
      </section>

      <section className="panel wide">
        <div className="tabs">
          {["overview", "metrics", "endpoints", "events", "threats", "settings"].map((item) => (
            <button key={item} className={tab === item ? "active" : ""} onClick={() => setTab(item)}>
              {item === "overview" ? "Преглед" : item === "metrics" ? "Метрики" : item === "endpoints" ? "Устройства" : item === "events" ? "Събития" : item === "threats" ? "Заплахи" : "Настройки"}
            </button>
          ))}
        </div>

        {tab === "overview" && (
          <>
            <div className="firewall-status-grid">
              <div><span>Критични за 24 ч</span><strong>{formatNumber(status.critical_24h)}</strong></div>
              <div><span>Високи за 24 ч</span><strong>{formatNumber(status.high_24h)}</strong></div>
              <div><span>С уязвимости</span><strong>{formatNumber(status.vulnerable_endpoints)}</strong></div>
              <div><span>Не са се свързвали</span><strong>{formatNumber(status.never_connected)}</strong></div>
              <div><span>Последно събитие</span><strong>{formatDate(status.last_event)}</strong></div>
              <div><span>Мениджър</span><strong>{settings.manager_url || "не е зададен"}</strong></div>
            </div>
            <EDREventsTable rows={(data.edrEvents || []).slice(0, 8)} onSelect={setSelectedEvent} />
          </>
        )}

        {tab === "metrics" && <CrowdSecMetricsPanel metrics={data.crowdsecMetrics} onRefresh={actions.reload} />}

        {tab === "endpoints" && <EDREndpointsTable rows={data.edrEndpoints || []} onSelect={setSelectedEndpoint} />}

        {tab === "events" && (
          <>
            <div className="form-grid compact-filters">
              <Field label="Важност"><SelectInput value={filters.severity} onChange={(value) => setFilters((c) => ({ ...c, severity: value }))}><option value="">Всички</option><option value="informational">Инфо</option><option value="low">Ниска</option><option value="medium">Средна</option><option value="high">Висока</option><option value="critical">Критична</option></SelectInput></Field>
              <Field label="Категория"><TextInput value={filters.category} onChange={(value) => setFilters((c) => ({ ...c, category: value }))} /></Field>
              <Field label="Устройство"><TextInput value={filters.endpoint} onChange={(value) => setFilters((c) => ({ ...c, endpoint: value }))} /></Field>
              <Field label="IP източник"><TextInput value={filters.source_ip} onChange={(value) => setFilters((c) => ({ ...c, source_ip: value }))} /></Field>
              <Field label="Търсене"><TextInput value={filters.search} onChange={(value) => setFilters((c) => ({ ...c, search: value }))} /></Field>
            </div>
            <EDREventsTable rows={filteredEvents} onSelect={setSelectedEvent} />
          </>
        )}

        {tab === "threats" && <EDRThreatsTable rows={data.edrThreats || []} onRefresh={actions.reload} />}

        {tab === "settings" && (
          <div className="settings-grid">
            <Field label="Доставчик"><TextInput value="Wazuh" onChange={() => {}} /></Field>
            <Field label="Manager URL"><TextInput value={draft.manager_url} onChange={(value) => setDraft((c) => ({ ...c, manager_url: value }))} /></Field>
            <Field label="Таймаут на агент, мин"><TextInput type="number" value={draft.agent_offline_timeout_minutes} onChange={(value) => setDraft((c) => ({ ...c, agent_offline_timeout_minutes: Number(value) }))} /></Field>
            <Field label="Съхранявай събития, дни"><TextInput type="number" value={draft.event_retention_days} onChange={(value) => setDraft((c) => ({ ...c, event_retention_days: Number(value) }))} /></Field>
            <label className="check-row"><input type="checkbox" checked={draft.automatic_refresh} onChange={(event) => setDraft((c) => ({ ...c, automatic_refresh: event.target.checked }))} /><span>Автообновяване</span></label>
            <div className="panel-actions"><button className="primary" onClick={saveSettings}><Save size={16} /><span>Запази настройките</span></button></div>
          </div>
        )}
      </section>

      {selectedEndpoint && <EDREndpointDetails endpoint={selectedEndpoint} events={data.edrEvents || []} vulnerabilities={data.edrVulnerabilities || []} onClose={() => setSelectedEndpoint(null)} />}
      {selectedEvent && <EDREventDetails event={selectedEvent} onClose={() => setSelectedEvent(null)} onBlock={blockEventIp} />}
    </ModuleLayout>
  );
}

function CrowdSecMetricsPanel({ metrics, onRefresh }) {
  if (!metrics) return <EmptyState label="Метриките на CrowdSec още не са заредени." />;

  return (
    <div className="crowdsec-metrics">
      <div className="panel-heading">
        <div>
          <h2>Метрики CrowdSec</h2>
          <span>Данни от командата {metrics.command || "cscli metrics"}. Обновено: {formatDate(metrics.generated_at)}</span>
        </div>
        <button className="secondary" type="button" onClick={onRefresh}>
          <RefreshCw size={16} />
          <span>Обнови</span>
        </button>
      </div>

      {!metrics.ok && (
        <div className="notice warn">
          {metrics.error || "CrowdSec не върна метрики. Инсталирайте cscli в backend контейнера или свържете контейнера към работещ CrowdSec."}
        </div>
      )}

      {metrics.sections?.map((section) => (
        <section className="metric-section" key={section.title}>
          <div className="split-heading">
            <h2>{section.title}</h2>
            <span>{formatNumber(section.rows?.length)} реда</span>
          </div>
          <div className="data-table metric-table">
            <div className="table-row table-head" style={{ gridTemplateColumns: `repeat(${Math.max(section.columns.length, 1)}, minmax(120px, 1fr))` }}>
              {section.columns.map((column) => <span key={column}>{column}</span>)}
            </div>
            {(section.rows || []).map((row, index) => (
              <div className="table-row" key={`${section.title}-${index}`} style={{ gridTemplateColumns: `repeat(${Math.max(section.columns.length, 1)}, minmax(120px, 1fr))` }}>
                {section.columns.map((column) => <span key={column}>{row[column] || "-"}</span>)}
              </div>
            ))}
            {!section.rows?.length && <EmptyState label="В тази секция все още няма редове." />}
          </div>
        </section>
      ))}

      {metrics.ok && !metrics.sections?.length && <EmptyState label="cscli metrics се изпълни, но не са намерени таблични секции." />}
    </div>
  );
}

function EDREndpointsTable({ rows, onSelect }) {
  if (!rows.length) return <EmptyState label="Все още няма endpoint устройства. Добавете устройство или изпратете телеметрия през API." />;
  return (
    <div className="data-table edr-endpoints-table">
      <div className="table-row table-head"><span>Име</span><span>IP</span><span>ОС</span><span>Агент</span><span>Версия</span><span>Бил онлайн</span><span>Защита</span><span>Заплахи</span><span>CVE</span></div>
      {rows.map((row) => (
        <button className="table-row table-button" key={row.id} onClick={() => onSelect(row)}>
          <strong>{row.hostname}</strong><span>{row.ip}</span><span>{row.os || "-"}</span><span>{agentStatusText[row.status] || row.status}</span><span>{row.agent_version || "-"}</span><span>{formatDate(row.last_seen)}</span><span>{endpointSecurityText[row.security_status] || row.security_status}</span><span>{formatNumber(row.threats_count)}</span><span>{formatNumber(row.vulnerabilities_count)}</span>
        </button>
      ))}
    </div>
  );
}

function EDREventsTable({ rows, onSelect }) {
  if (!rows.length) return <EmptyState label="Все още няма EDR събития." />;
  return (
    <div className="data-table edr-events-table">
      <div className="table-row table-head"><span>Време</span><span>Важност</span><span>Устройство</span><span>Събитие</span><span>Категория</span><span>Процес</span><span>Файл/IP</span><span>Действие</span></div>
      {rows.map((row) => (
        <button className="table-row table-button" key={row.id} onClick={() => onSelect(row)}>
          <span>{formatDate(row.timestamp)}</span><span><Pill value={row.severity} type="severity" /></span><strong>{row.endpoint_hostname || "-"}</strong><span>{row.title}</span><span>{row.category}</span><span>{row.process_name || "-"}</span><span>{row.file_path || row.source_ip || "-"}</span><span>{decisionText[row.action] || row.action}</span>
        </button>
      ))}
    </div>
  );
}

function EDRThreatsTable({ rows, onRefresh }) {
  if (!rows.length) return <EmptyState label="Все още няма активни заплахи." />;
  return (
    <div className="data-table edr-threats-table">
      <div className="table-row table-head"><span>Заплаха</span><span>Устройство</span><span>Категория</span><span>Важност</span><span>Статус</span></div>
      {rows.map((row) => (
        <div className="table-row" key={row.id}>
          <strong>{row.title}</strong><span>{row.endpoint_hostname || "-"}</span><span>{row.category}</span><span><Pill value={row.severity} type="severity" /></span>
          <span><SelectInput value={row.status} onChange={async (value) => { await apiRequest(`/edr/threats/${row.id}/status/`, { method: "PUT", body: JSON.stringify({ status: value }) }); onRefresh(); }}><option value="new">{threatStatusText.new}</option><option value="investigating">{threatStatusText.investigating}</option><option value="resolved">{threatStatusText.resolved}</option><option value="ignored">{threatStatusText.ignored}</option><option value="blocked">{threatStatusText.blocked}</option></SelectInput></span>
        </div>
      ))}
    </div>
  );
}

function EDREndpointDetails({ endpoint, events, vulnerabilities, onClose }) {
  const endpointEvents = events.filter((event) => event.endpoint === endpoint.id).slice(0, 8);
  const endpointVulns = vulnerabilities.filter((item) => item.endpoint === endpoint.id).slice(0, 8);
  return (
    <section className="panel wide detail-panel">
      <div className="panel-heading"><div><h2>{endpoint.hostname}</h2><span>{endpoint.ip} · {endpoint.os || "ОС не е посочена"}</span></div><button className="secondary" onClick={onClose}><X size={15} /><span>Затвори</span></button></div>
      <div className="firewall-status-grid">
        <div><span>ID на агент</span><strong>{endpoint.agent_id || endpoint.external_id || "-"}</strong></div><div><span>Версия</span><strong>{endpoint.agent_version || "-"}</strong></div><div><span>Архитектура</span><strong>{endpoint.architecture || "-"}</strong></div><div><span>Потребител</span><strong>{endpoint.logged_in_user || "-"}</strong></div><div><span>Първо свързване</span><strong>{formatDate(endpoint.first_seen)}</strong></div><div><span>Статус</span><strong>{endpointSecurityText[endpoint.security_status] || endpoint.security_status}</strong></div>
      </div>
      <h3>Последни събития</h3>
      <EDREventsTable rows={endpointEvents} onSelect={() => {}} />
      <h3>Уязвимости</h3>
      <div className="data-table edr-vulns-table">
        {endpointVulns.map((item) => <div className="table-row" key={item.id}><strong>{item.cve}</strong><span>{item.package}</span><span>{item.installed_version}</span><span>{item.fixed_version || "-"}</span><span><Pill value={item.severity} type="severity" /></span><span>{item.status}</span></div>)}
        {!endpointVulns.length && <EmptyState label="Все още няма уязвимости за този endpoint." />}
      </div>
    </section>
  );
}

function EDREventDetails({ event, onClose, onBlock }) {
  return (
    <section className="panel wide detail-panel">
      <div className="panel-heading"><div><h2>{event.title}</h2><span>{event.endpoint_hostname || "-"} · {formatDate(event.timestamp)}</span></div><button className="secondary" onClick={onClose}><X size={15} /><span>Затвори</span></button></div>
      <div className="firewall-status-grid">
        <div><span>Важност</span><strong>{severityText[event.severity] || event.severity}</strong></div><div><span>Категория</span><strong>{event.category}</strong></div><div><span>Потребител</span><strong>{event.username || "-"}</strong></div><div><span>Процес</span><strong>{event.process_name || "-"}</strong></div><div><span>Файл</span><strong>{event.file_path || "-"}</strong></div><div><span>Хеш</span><strong>{event.file_hash || "-"}</strong></div>
      </div>
      <p>{event.description}</p>
      <div className="firewall-actions"><button className="primary" onClick={() => onBlock(event)}><Shield size={16} /><span>Блокирай IP</span></button></div>
      <details className="technical-details"><summary>Технически данни</summary><pre>{JSON.stringify(event.raw_event || {}, null, 2)}</pre></details>
    </section>
  );
}

function EDRPage({ data, actions }) {
  const blank = { name: "", telemetry_level: "standard", block_usb: false, block_script_interpreters: true, quarantine_on_malware: true, protected_paths: "/etc\n/var/www" };
  const [policy, setPolicy] = useState(blank);
  const [editingId, setEditingId] = useState(null);
  const [probe, setProbe] = useState({ hostname: "", ip_address: "", operating_system: "", owner: "", process_name: "", command_line: "", threat_name: "", severity: "low" });
  const [result, setResult] = useState(null);

  const savePolicy = async (event) => {
    event.preventDefault();
    if (editingId) await apiPatch(`/edr/policies/${editingId}/`, policy);
    else await apiPost("/edr/policies/", policy);
    setPolicy(blank);
    setEditingId(null);
    actions.reload();
  };

  return (
    <ModuleLayout moduleKey="edr" data={data} actions={actions}>
      <section className="panel">
        <div className="panel-heading">
          <h2>{editingId ? "Изменить политику" : "Новая политика"}</h2>
        </div>
        <form className="form-grid" onSubmit={savePolicy}>
          <Field label="Название">
            <TextInput value={policy.name} onChange={(value) => setPolicy((current) => ({ ...current, name: value }))} placeholder="Например: базовая защита ПК" />
          </Field>
          <Field label="Уровень телеметрии">
            <SelectInput value={policy.telemetry_level} onChange={(value) => setPolicy((current) => ({ ...current, telemetry_level: value }))}>
              <option value="minimal">Минимальный</option>
              <option value="standard">Стандартный</option>
              <option value="verbose">Подробный</option>
            </SelectInput>
          </Field>
          <label className="check-row">
            <input type="checkbox" checked={policy.block_usb} onChange={(event) => setPolicy((current) => ({ ...current, block_usb: event.target.checked }))} />
            <span>Блокировать USB</span>
          </label>
          <label className="check-row">
            <input type="checkbox" checked={policy.block_script_interpreters} onChange={(event) => setPolicy((current) => ({ ...current, block_script_interpreters: event.target.checked }))} />
            <span>Ограничить скрипты</span>
          </label>
          <label className="check-row">
            <input type="checkbox" checked={policy.quarantine_on_malware} onChange={(event) => setPolicy((current) => ({ ...current, quarantine_on_malware: event.target.checked }))} />
            <span>Карантин угроз</span>
          </label>
          <FormActions editing={Boolean(editingId)} disabled={!policy.name} onCancel={() => { setPolicy(blank); setEditingId(null); }} />
        </form>
      </section>

      <ProbePanel title="Добавить телеметрию устройства" kind="edr" result={result} buttonLabel="Принять" disabled={!probe.hostname} onRun={async () => setResult(await apiPost("/edr/telemetry/", probe))}>
        <Field label="Имя устройства">
          <TextInput value={probe.hostname} onChange={(value) => setProbe((current) => ({ ...current, hostname: value }))} placeholder="Например: laptop-ivanov" />
        </Field>
        <Field label="IP адрес">
          <TextInput value={probe.ip_address} onChange={(value) => setProbe((current) => ({ ...current, ip_address: value }))} placeholder="Например: 10.0.0.30" />
        </Field>
        <Field label="Операционная система">
          <TextInput value={probe.operating_system} onChange={(value) => setProbe((current) => ({ ...current, operating_system: value }))} />
        </Field>
        <Field label="Процесс">
          <TextInput value={probe.process_name} onChange={(value) => setProbe((current) => ({ ...current, process_name: value }))} />
        </Field>
        <Field label="Команда">
          <TextInput value={probe.command_line} onChange={(value) => setProbe((current) => ({ ...current, command_line: value }))} placeholder="Командная строка процесса" />
        </Field>
        <Field label="Название угрозы">
          <TextInput value={probe.threat_name} onChange={(value) => setProbe((current) => ({ ...current, threat_name: value }))} />
        </Field>
      </ProbePanel>

      <section className="panel wide">
        <div className="panel-heading">
          <h2>Политики и устройства</h2>
          <span>{data.edrPolicies.length} политик · {data.assets.length} устройств</span>
        </div>
        <RuleCards
          rows={data.edrPolicies}
          endpoint="/edr/policies"
          onRefresh={actions.reload}
          onEdit={(row) => { setPolicy(row); setEditingId(row.id); }}
          emptyLabel="Политик пока нет. Добавьте первую EDR-политику."
          showHits={false}
          fields={[
            { key: "telemetry_level", label: "Телеметрия" },
            { key: "block_usb", label: "USB", render: (row) => (row.block_usb ? "блокируется" : "разрешен") },
            { key: "block_script_interpreters", label: "Скрипты", render: (row) => (row.block_script_interpreters ? "ограничены" : "разрешены") },
            { key: "quarantine_on_malware", label: "Угрозы", render: (row) => (row.quarantine_on_malware ? "карантин" : "только алерт") },
          ]}
        />
        <DeviceCards assets={data.assets} />
      </section>
    </ModuleLayout>
  );
}

function WebFilterPage({ data, actions }) {
  const blank = { name: "", priority: 100, match_type: "domain", pattern: "", category: "", action: "block" };
  const [rule, setRule] = useState(blank);
  const [editingId, setEditingId] = useState(null);
  const [probe, setProbe] = useState({ source_ip: "", url: "" });
  const [result, setResult] = useState(null);
  const rules = data.webRules || [];
  const categories = new Set(rules.map((item) => item.category).filter(Boolean));

  const saveRule = async (event) => {
    event.preventDefault();
    if (editingId) await apiPatch(`/web-filter/rules/${editingId}/`, rule);
    else await apiPost("/web-filter/rules/", rule);
    setRule(blank);
    setEditingId(null);
    actions.reload();
  };

  return (
    <ModuleLayout moduleKey="web_filter" data={data} actions={actions}>
      <section className="panel firewall-console">
        <div className="firewall-topbar">
          <div>
            <h2>Web Filter: интернет достъп</h2>
            <p>Политики за ограничаване на нежелани сайтове по домейни, фрази, категории и действия.</p>
          </div>
          <span className="plain-status">Винаги включено</span>
        </div>
        <div className="firewall-status-grid">
          <div><span>Общо правила</span><strong>{formatNumber(rules.length)}</strong></div>
          <div><span>Блокиращи</span><strong>{formatNumber(rules.filter((item) => item.action === "block").length)}</strong></div>
          <div><span>Разрешаващи</span><strong>{formatNumber(rules.filter((item) => item.action === "allow").length)}</strong></div>
          <div><span>За преглед</span><strong>{formatNumber(rules.filter((item) => item.action === "review").length)}</strong></div>
          <div><span>Категории</span><strong>{formatNumber(categories.size)}</strong></div>
          <div><span>Последна промяна</span><strong>{formatDate(rules.map((item) => item.updated_at).filter(Boolean).sort().at(-1))}</strong></div>
        </div>
      </section>

      <section className="panel">
        <div className="panel-heading">
          <h2>{editingId ? "Промяна на правило за сайт" : "Ново правило за сайт"}</h2>
        </div>
        <form className="form-grid" onSubmit={saveRule}>
          <Field label="Име">
            <TextInput value={rule.name} onChange={(value) => setRule((current) => ({ ...current, name: value }))} placeholder="Например: блокиране на рискови сайтове" />
          </Field>
          <Field label="Как да търси">
            <SelectInput value={rule.match_type} onChange={(value) => setRule((current) => ({ ...current, match_type: value }))}>
              <option value="domain">По домейн</option>
              <option value="contains">По част от адреса</option>
              <option value="regex">По шаблон</option>
            </SelectInput>
          </Field>
          <Field label="Домейн или фраза">
            <TextInput value={rule.pattern} onChange={(value) => setRule((current) => ({ ...current, pattern: value }))} placeholder="example.com" />
          </Field>
          <Field label="Категория">
            <TextInput value={rule.category} onChange={(value) => setRule((current) => ({ ...current, category: value }))} placeholder="Социални мрежи, фишинг, игри" />
          </Field>
          <Field label="Действие">
            <SelectInput value={rule.action} onChange={(value) => setRule((current) => ({ ...current, action: value }))}>
              <option value="allow">Разреши</option>
              <option value="block">Блокирай</option>
              <option value="review">Изпрати за преглед</option>
            </SelectInput>
          </Field>
          <FormActions editing={Boolean(editingId)} disabled={!rule.name || !rule.pattern} onCancel={() => { setRule(blank); setEditingId(null); }} />
        </form>
      </section>

      <ProbePanel title="Провери сайт" kind="web" result={result} disabled={!probe.url} onRun={async () => setResult(await apiPost("/web-filter/evaluate/", probe))}>
        <Field label="IP на потребител">
          <TextInput value={probe.source_ip} onChange={(value) => setProbe((current) => ({ ...current, source_ip: value }))} placeholder="Например: 10.0.0.40" />
        </Field>
        <Field label="Адрес на сайт">
          <TextInput value={probe.url} onChange={(value) => setProbe((current) => ({ ...current, url: value }))} placeholder="https://example.com" />
        </Field>
      </ProbePanel>

      <section className="panel wide">
        <div className="panel-heading">
          <h2>Правила за сайтове</h2>
          <span>{data.webRules.length}</span>
        </div>
        <RuleCards
          rows={data.webRules}
          endpoint="/web-filter/rules"
          onRefresh={actions.reload}
          onEdit={(row) => { setRule(row); setEditingId(row.id); }}
          emptyLabel="Все още няма правила за сайтове."
          fields={[
            { key: "action", label: "Действие", render: (row) => <Pill value={row.action} /> },
            { key: "match_type", label: "Търсене" },
            { key: "pattern", label: "Домейн или фраза" },
            { key: "category", label: "Категория" },
          ]}
        />
      </section>
    </ModuleLayout>
  );
}

function AccessPage({ data, actions }) {
  const blank = { name: "", priority: 100, network_type: "vpn", group: "any", mfa_required: true, effect: "allow" };
  const [rule, setRule] = useState(blank);
  const [editingId, setEditingId] = useState(null);
  const [probe, setProbe] = useState({ username: "", group: "", source_ip: "", network_type: "vpn", mfa_verified: false });
  const [result, setResult] = useState(null);
  const rules = data.accessRules || [];
  const networkTypes = new Set(rules.map((item) => item.network_type).filter(Boolean));

  const saveRule = async (event) => {
    event.preventDefault();
    if (editingId) await apiPatch(`/access/rules/${editingId}/`, rule);
    else await apiPost("/access/rules/", rule);
    setRule(blank);
    setEditingId(null);
    actions.reload();
  };

  return (
    <ModuleLayout moduleKey="access" data={data} actions={actions}>
      <section className="panel firewall-console">
        <div className="firewall-topbar">
          <div>
            <h2>IAM/MFA: управление на достъпа</h2>
            <p>Централизирани правила за потребители, групи, мрежови връзки и многофакторна автентикация.</p>
          </div>
          <span className="plain-status">Винаги включено</span>
        </div>
        <div className="firewall-status-grid">
          <div><span>Общо правила</span><strong>{formatNumber(rules.length)}</strong></div>
          <div><span>Изискват MFA</span><strong>{formatNumber(rules.filter((item) => item.mfa_required).length)}</strong></div>
          <div><span>Разрешаващи</span><strong>{formatNumber(rules.filter((item) => item.effect === "allow").length)}</strong></div>
          <div><span>Забраняващи</span><strong>{formatNumber(rules.filter((item) => item.effect === "deny").length)}</strong></div>
          <div><span>Типове връзки</span><strong>{formatNumber(networkTypes.size)}</strong></div>
          <div><span>Последна промяна</span><strong>{formatDate(rules.map((item) => item.updated_at).filter(Boolean).sort().at(-1))}</strong></div>
        </div>
      </section>

      <section className="panel">
        <div className="panel-heading">
          <h2>{editingId ? "Промяна на правило за достъп" : "Ново правило за достъп"}</h2>
        </div>
        <form className="form-grid" onSubmit={saveRule}>
          <Field label="Име">
            <TextInput value={rule.name} onChange={(value) => setRule((current) => ({ ...current, name: value }))} placeholder="Например: VPN само с MFA" />
          </Field>
          <Field label="Тип връзка">
            <SelectInput value={rule.network_type} onChange={(value) => setRule((current) => ({ ...current, network_type: value }))}>
              <option value="any">Всяка</option>
              <option value="wired">Кабелна</option>
              <option value="wireless">Wi-Fi</option>
              <option value="vpn">VPN</option>
              <option value="admin">Административна</option>
            </SelectInput>
          </Field>
          <Field label="Група">
            <TextInput value={rule.group} onChange={(value) => setRule((current) => ({ ...current, group: value }))} placeholder="any или employees" />
          </Field>
          <Field label="Решение">
            <SelectInput value={rule.effect} onChange={(value) => setRule((current) => ({ ...current, effect: value }))}>
              <option value="allow">Разреши</option>
              <option value="deny">Забрани</option>
              <option value="review">За преглед</option>
            </SelectInput>
          </Field>
          <label className="check-row">
            <input type="checkbox" checked={rule.mfa_required} onChange={(event) => setRule((current) => ({ ...current, mfa_required: event.target.checked }))} />
            <span>Изисквай MFA</span>
          </label>
          <FormActions editing={Boolean(editingId)} disabled={!rule.name} onCancel={() => { setRule(blank); setEditingId(null); }} />
        </form>
      </section>

      <ProbePanel title="Провери достъп" kind="access" result={result} disabled={!probe.username} onRun={async () => setResult(await apiPost("/access/evaluate/", probe))}>
        <Field label="Потребител">
          <TextInput value={probe.username} onChange={(value) => setProbe((current) => ({ ...current, username: value }))} />
        </Field>
        <Field label="Група">
          <TextInput value={probe.group} onChange={(value) => setProbe((current) => ({ ...current, group: value }))} />
        </Field>
        <Field label="IP адрес">
          <TextInput value={probe.source_ip} onChange={(value) => setProbe((current) => ({ ...current, source_ip: value }))} />
        </Field>
        <Field label="Тип връзка">
          <SelectInput value={probe.network_type} onChange={(value) => setProbe((current) => ({ ...current, network_type: value }))}>
            <option value="wired">Кабелна</option>
            <option value="wireless">Wi-Fi</option>
            <option value="vpn">VPN</option>
            <option value="admin">Административна</option>
          </SelectInput>
        </Field>
        <label className="check-row">
          <input type="checkbox" checked={probe.mfa_verified} onChange={(event) => setProbe((current) => ({ ...current, mfa_verified: event.target.checked }))} />
          <span>MFA премината</span>
        </label>
      </ProbePanel>

      <section className="panel wide">
        <div className="panel-heading">
          <h2>Правила за достъп</h2>
          <span>{data.accessRules.length}</span>
        </div>
        <RuleCards
          rows={data.accessRules}
          endpoint="/access/rules"
          onRefresh={actions.reload}
          onEdit={(row) => { setRule(row); setEditingId(row.id); }}
          emptyLabel="Все още няма правила за достъп."
          fields={[
            { key: "effect", label: "Решение", render: (row) => <Pill value={row.effect} /> },
            { key: "network_type", label: "Връзка" },
            { key: "group", label: "Група" },
            { key: "mfa_required", label: "MFA", render: (row) => (row.mfa_required ? "изисква се" : "не се изисква") },
          ]}
        />
      </section>
      <UserManagementPanel users={data.users || []} onRefresh={actions.reload} />
    </ModuleLayout>
  );
}

function UserManagementPanel({ users, onRefresh }) {
  const [draft, setDraft] = useState({ username: "", password: "", email: "", first_name: "", last_name: "", is_staff: false, is_active: true });
  const [message, setMessage] = useState(null);

  const createUser = async (event) => {
    event.preventDefault();
    setMessage(null);
    try {
      await apiPost("/auth/users/", draft);
      setDraft({ username: "", password: "", email: "", first_name: "", last_name: "", is_staff: false, is_active: true });
      setMessage({ tone: "ok", text: "Потребителят е създаден" });
      onRefresh();
    } catch (error) {
      setMessage({ tone: "danger", text: error.message });
    }
  };

  return (
    <section className="panel wide">
      <div className="panel-heading">
        <div>
          <h2>Потребители</h2>
          <span>Локални акаунти за вход в административния интерфейс.</span>
        </div>
        <span className="plain-status">{formatNumber(users.length)} акаунта</span>
      </div>
      {message && <div className={`notice ${message.tone}`}>{message.text}</div>}
      <form className="form-grid user-form" onSubmit={createUser}>
        <Field label="Потребителско име">
          <TextInput value={draft.username} onChange={(value) => setDraft((current) => ({ ...current, username: value }))} placeholder="ivan.petrov" />
        </Field>
        <Field label="Парола">
          <TextInput type="password" value={draft.password} onChange={(value) => setDraft((current) => ({ ...current, password: value }))} placeholder="минимум 8 символа" />
        </Field>
        <Field label="Имейл">
          <TextInput value={draft.email} onChange={(value) => setDraft((current) => ({ ...current, email: value }))} placeholder="user@example.local" />
        </Field>
        <Field label="Име">
          <TextInput value={draft.first_name} onChange={(value) => setDraft((current) => ({ ...current, first_name: value }))} />
        </Field>
        <Field label="Фамилия">
          <TextInput value={draft.last_name} onChange={(value) => setDraft((current) => ({ ...current, last_name: value }))} />
        </Field>
        <label className="check-row">
          <input type="checkbox" checked={draft.is_staff} onChange={(event) => setDraft((current) => ({ ...current, is_staff: event.target.checked }))} />
          <span>Администратор</span>
        </label>
        <FormActions disabled={!draft.username || draft.password.length < 8} />
      </form>
      <div className="data-table users-table">
        <div className="table-row table-head"><span>Потребител</span><span>Име</span><span>Имейл</span><span>Роля</span><span>Статус</span><span>Последен вход</span></div>
        {users.map((user) => (
          <div className="table-row" key={user.id}>
            <strong>{user.username}</strong>
            <span>{user.full_name}</span>
            <span>{user.email || "-"}</span>
            <span>{user.is_staff ? "Администратор" : "Оператор"}</span>
            <span>{user.is_active ? "Активен" : "Изключен"}</span>
            <span>{formatDate(user.last_login)}</span>
          </div>
        ))}
        {!users.length && <EmptyState label="Все още няма потребители." />}
      </div>
    </section>
  );
}

function SIEMPage({ data, actions }) {
  const blankSource = { name: "", component: "siem", parser: "json", enabled: true };
  const blankRule = { name: "", component: "siem", pattern: "", threshold: 3, window_minutes: 10, severity: "high" };
  const [source, setSource] = useState(blankSource);
  const [sourceEditId, setSourceEditId] = useState(null);
  const [rule, setRule] = useState(blankRule);
  const [ruleEditId, setRuleEditId] = useState(null);
  const [log, setLog] = useState({ source: "", component: "siem", source_ip: "", destination: "", event_type: "", severity: "low", raw_message: "" });
  const [result, setResult] = useState(null);

  const saveSource = async (event) => {
    event.preventDefault();
    if (sourceEditId) await apiPatch(`/siem/log-sources/${sourceEditId}/`, source);
    else await apiPost("/siem/log-sources/", source);
    setSource(blankSource);
    setSourceEditId(null);
    actions.reload();
  };

  const saveRule = async (event) => {
    event.preventDefault();
    if (ruleEditId) await apiPatch(`/siem/correlation-rules/${ruleEditId}/`, rule);
    else await apiPost("/siem/correlation-rules/", rule);
    setRule(blankRule);
    setRuleEditId(null);
    actions.reload();
  };

  return (
    <ModuleLayout moduleKey="siem" data={data} actions={actions}>
      <section className="panel">
        <div className="panel-heading">
          <h2>{sourceEditId ? "Изменить источник" : "Новый источник журналов"}</h2>
        </div>
        <form className="form-grid" onSubmit={saveSource}>
          <Field label="Название источника">
            <TextInput value={source.name} onChange={(value) => setSource((current) => ({ ...current, name: value }))} placeholder="Например: edge-nginx" />
          </Field>
          <Field label="Откуда приходят данные">
            <ModuleSelect value={source.component} onChange={(value) => setSource((current) => ({ ...current, component: value }))} />
          </Field>
          <Field label="Формат">
            <SelectInput value={source.parser} onChange={(value) => setSource((current) => ({ ...current, parser: value }))}>
              <option value="json">JSON</option>
              <option value="syslog">Syslog</option>
              <option value="plain">Обычный текст</option>
            </SelectInput>
          </Field>
          <FormActions editing={Boolean(sourceEditId)} disabled={!source.name} onCancel={() => { setSource(blankSource); setSourceEditId(null); }} />
        </form>
      </section>

      <section className="panel">
        <div className="panel-heading">
          <h2>{ruleEditId ? "Изменить корреляцию" : "Новая корреляция"}</h2>
        </div>
        <form className="form-grid" onSubmit={saveRule}>
          <Field label="Название">
            <TextInput value={rule.name} onChange={(value) => setRule((current) => ({ ...current, name: value }))} placeholder="Например: много отказов входа" />
          </Field>
          <Field label="Модуль">
            <ModuleSelect value={rule.component} onChange={(value) => setRule((current) => ({ ...current, component: value }))} />
          </Field>
          <Field label="Что искать в журналах">
            <TextInput value={rule.pattern} onChange={(value) => setRule((current) => ({ ...current, pattern: value }))} placeholder="failed, denied, blocked" />
          </Field>
          <Field label="Сколько раз">
            <TextInput type="number" value={rule.threshold} onChange={(value) => setRule((current) => ({ ...current, threshold: Number(value) }))} />
          </Field>
          <Field label="За минут">
            <TextInput type="number" value={rule.window_minutes} onChange={(value) => setRule((current) => ({ ...current, window_minutes: Number(value) }))} />
          </Field>
          <Field label="Риск">
            <SelectInput value={rule.severity} onChange={(value) => setRule((current) => ({ ...current, severity: value }))}>
              <option value="medium">Средний</option>
              <option value="high">Высокий</option>
              <option value="critical">Критичный</option>
            </SelectInput>
          </Field>
          <FormActions editing={Boolean(ruleEditId)} disabled={!rule.name || !rule.pattern} onCancel={() => { setRule(blankRule); setRuleEditId(null); }} />
        </form>
      </section>

      <ProbePanel title="Добавить запись журнала" kind="siem" result={result} buttonLabel="Принять журнал" disabled={!log.raw_message} onRun={async () => setResult(await apiPost("/ingest/logs/", log))}>
        <Field label="Источник">
          <TextInput value={log.source} onChange={(value) => setLog((current) => ({ ...current, source: value }))} placeholder="Например: vpn-gateway" />
        </Field>
        <Field label="Модуль">
          <ModuleSelect value={log.component} onChange={(value) => setLog((current) => ({ ...current, component: value }))} />
        </Field>
        <Field label="IP источника">
          <TextInput value={log.source_ip} onChange={(value) => setLog((current) => ({ ...current, source_ip: value }))} placeholder="IP из журнала" />
        </Field>
        <Field label="Тип события">
          <TextInput value={log.event_type} onChange={(value) => setLog((current) => ({ ...current, event_type: value }))} placeholder="Например: отказ входа" />
        </Field>
        <Field label="Риск">
          <SelectInput value={log.severity} onChange={(value) => setLog((current) => ({ ...current, severity: value }))}>
            <option value="low">Низкий</option>
            <option value="medium">Средний</option>
            <option value="high">Высокий</option>
            <option value="critical">Критичный</option>
          </SelectInput>
        </Field>
        <Field label="Сообщение">
          <textarea value={log.raw_message} onChange={(event) => setLog((current) => ({ ...current, raw_message: event.target.value }))} rows={3} placeholder="Текст записи журнала" />
        </Field>
      </ProbePanel>

      <section className="panel wide">
        <div className="split-heading">
          <h2>Источники и корреляции</h2>
          <span>{data.logSources.length} источников · {data.correlations.length} правил</span>
        </div>
        <RuleCards
          rows={data.logSources}
          endpoint="/siem/log-sources"
          onRefresh={actions.reload}
          onEdit={(row) => { setSource(row); setSourceEditId(row.id); }}
          emptyLabel="Источников журналов пока нет."
          showHits={false}
          fields={[
            { key: "component", label: "Модуль", render: (row) => moduleTitle(row.component) },
            { key: "parser", label: "Формат" },
            { key: "last_seen", label: "Последний прием", render: (row) => formatDate(row.last_seen) },
          ]}
        />
        <RuleCards
          rows={data.correlations}
          endpoint="/siem/correlation-rules"
          onRefresh={actions.reload}
          onEdit={(row) => { setRule(row); setRuleEditId(row.id); }}
          emptyLabel="Корреляций пока нет."
          fields={[
            { key: "component", label: "Модуль", render: (row) => moduleTitle(row.component) },
            { key: "pattern", label: "Ищем" },
            { key: "threshold", label: "Сколько раз" },
            { key: "severity", label: "Риск", render: (row) => <Pill value={row.severity} type="severity" /> },
          ]}
        />
      </section>
    </ModuleLayout>
  );
}

function DeviceCards({ assets }) {
  return (
    <div className="device-grid">
      {assets.map((asset) => (
        <article key={asset.id} className="device-card">
          <div>
            <Server size={18} />
            <Pill value={asset.risk_level} type="severity" />
          </div>
          <h3>{asset.name}</h3>
          <p>{asset.ip_address} · {asset.operating_system || "система не указана"}</p>
          <strong>{asset.edr_status}</strong>
          <span>{formatDate(asset.last_seen)}</span>
        </article>
      ))}
      {assets.length === 0 && <EmptyState label="Устройств пока нет. Они появятся после приема EDR-телеметрии." />}
    </div>
  );
}

function EventCards({ rows, isLog = false }) {
  return (
    <div className="event-list">
      {rows.map((row) => (
        <article key={`${isLog ? "log" : "event"}-${row.id}`} className="event-card">
          <div className="event-main">
            <Pill value={row.severity} type="severity" />
            <div>
              <h3>{row.event_type}</h3>
              <p>{isLog ? row.raw_message : row.message}</p>
            </div>
          </div>
          <div className="event-meta">
            <span>{row.component_label || row.component_name || moduleTitle(row.component_key || row.component)}</span>
            <span>{row.source_ip || "0.0.0.0"} → {row.destination || "не указано"}</span>
            <span>{formatDate(isLog ? row.created_at : row.occurred_at)}</span>
          </div>
        </article>
      ))}
      {rows.length === 0 && <EmptyState label={isLog ? "Журналов пока нет." : "Событий пока нет."} />}
    </div>
  );
}

function App() {
  const [activeView, setActiveView] = useState("firewall");
  const [infoModal, setInfoModal] = useState(null);
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [data, setData] = useState({
    overview: null,
    firewallStatus: null,
    settings: [],
    components: [],
    firewallRules: [],
    ipsStatus: null,
    ipsEvents: [],
    ipsCategories: [],
    ipsCustomRules: [],
    ipsSettings: null,
    ipsRules: [],
    edrPolicies: [],
    edrStatus: null,
    edrEndpoints: [],
    edrEvents: [],
    edrThreats: [],
    edrVulnerabilities: [],
    edrSettings: null,
    crowdsecMetrics: null,
    webRules: [],
    accessRules: [],
    assets: [],
    events: [],
    firewallEvents: [],
    alerts: [],
    logSources: [],
    logs: [],
    correlations: [],
    users: [],
  });

  const loadData = async () => {
    setLoading(true);
    setError("");
    try {
      const [overview, firewallStatus, settings, components, firewallRules, firewallEvents, ipsStatus, ipsEvents, ipsCategories, ipsCustomRules, ipsSettings, ipsRules, edrPolicies, edrStatus, edrEndpoints, edrEvents, edrThreats, edrVulnerabilities, edrSettings, crowdsecMetrics, webRules, accessRules, assets, events, alerts, logSources, logs, correlations, users] = await Promise.all([
        apiGet("/dashboard/overview/"),
        apiGet("/firewall/status/"),
        apiGet("/module-settings/"),
        apiGet("/components/"),
        apiGet("/firewall/rules/"),
        apiGet("/firewall/events/"),
        apiGet("/ips/status/"),
        apiGet("/ips/events/"),
        apiGet("/ips/rules/categories/"),
        apiGet("/ips/custom-rules/"),
        apiGet("/ips/settings/"),
        apiGet("/ips/rules/"),
        apiGet("/edr/policies/"),
        apiGet("/edr/status/"),
        apiGet("/edr/endpoints/"),
        apiGet("/edr/events/"),
        apiGet("/edr/threats/"),
        apiGet("/edr/vulnerabilities/"),
        apiGet("/edr/settings/"),
        apiGet("/edr/crowdsec/metrics/"),
        apiGet("/web-filter/rules/"),
        apiGet("/access/rules/"),
        apiGet("/assets/"),
        apiGet("/events/"),
        apiGet("/alerts/"),
        apiGet("/siem/log-sources/"),
        apiGet("/siem/logs/"),
        apiGet("/siem/correlation-rules/"),
        apiGet("/auth/users/"),
      ]);
      setData({
        overview,
        firewallStatus,
        settings: normalizeList(settings),
        components: normalizeList(components),
        firewallRules: normalizeList(firewallRules),
        firewallEvents: normalizeList(firewallEvents),
        ipsStatus,
        ipsEvents: normalizeList(ipsEvents),
        ipsCategories: normalizeList(ipsCategories),
        ipsCustomRules: normalizeList(ipsCustomRules),
        ipsSettings,
        ipsRules: normalizeList(ipsRules),
        edrPolicies: normalizeList(edrPolicies),
        edrStatus,
        edrEndpoints: normalizeList(edrEndpoints),
        edrEvents: normalizeList(edrEvents),
        edrThreats: normalizeList(edrThreats),
        edrVulnerabilities: normalizeList(edrVulnerabilities),
        edrSettings,
        crowdsecMetrics,
        webRules: normalizeList(webRules),
        accessRules: normalizeList(accessRules),
        assets: normalizeList(assets),
        events: normalizeList(events),
        alerts: normalizeList(alerts),
        logSources: normalizeList(logSources),
        logs: normalizeList(logs),
        correlations: normalizeList(correlations),
        users: normalizeList(users),
      });
    } catch (currentError) {
      setError(currentError.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const boot = async () => {
      const token = getAuthToken();
      if (!token) {
        setLoading(false);
        return;
      }
      try {
        const currentUser = await apiGet("/auth/me/");
        setUser(currentUser);
        await loadData();
      } catch {
        localStorage.removeItem(AUTH_TOKEN_KEY);
        setUser(null);
        setLoading(false);
      }
    };
    boot();
  }, []);

  const saveSetting = async (id, body) => {
    await apiPatch(`/module-settings/${id}/`, body);
    loadData();
  };

  const overview = data.overview?.kpis || {};

  const page = {
    firewall: <FirewallPageV2 data={data} actions={{ reload: loadData, saveSetting }} />,
    ips: <IPSPageV2 data={data} actions={{ reload: loadData, saveSetting }} />,
    edr: <EDRPageV2 data={data} actions={{ reload: loadData, saveSetting }} />,
    web_filter: <WebFilterPage data={data} actions={{ reload: loadData, saveSetting }} />,
    access: <AccessPage data={data} actions={{ reload: loadData, saveSetting }} />,
  }[activeView];

  const handleLogin = async (currentUser) => {
    setUser(currentUser);
    await loadData();
  };

  const handleLogout = async () => {
    try {
      await apiPost("/auth/logout/", {});
    } catch {
      // Token can already be invalid; local cleanup is enough for the UI.
    }
    localStorage.removeItem(AUTH_TOKEN_KEY);
    setUser(null);
  };

  if (!user) {
    return <LoginPage onLogin={handleLogin} />;
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">
            <Network size={24} />
          </div>
          <div>
            <strong>SOC Control</strong>
            <span>Панел за защита</span>
          </div>
        </div>
        <nav>
          {modules.map((module) => {
            const Icon = module.icon;
            return (
              <button key={module.key} className={activeView === module.key ? "active" : ""} onClick={() => setActiveView(module.key)}>
                <Icon size={18} />
                <span>{module.title}</span>
              </button>
            );
          })}
        </nav>
        <div className="sidebar-info-actions">
          <button type="button" onClick={() => setInfoModal("project")}>
            <Landmark size={18} />
            <span>Проект BG16RFPR001-1.012-0189-C01</span>
          </button>
          <button type="button" onClick={() => setInfoModal("license")}>
            <FileText size={18} />
            <span>Лиценз NET Base 03.022 03-022-0134</span>
          </button>
        </div>
      </aside>

      <main>
        <header className="topbar">
          <div>
            <p>Център за киберсигурност</p>
            <h1>{moduleTitle(activeView)}</h1>
          </div>
          <div className="topbar-actions">
            <span className="user-chip">{user.full_name || user.username}</span>
            <button className="refresh-button" onClick={loadData}>
              <RefreshCw size={18} className={loading ? "spin" : ""} />
              <span>Обнови</span>
            </button>
            <button className="secondary" onClick={handleLogout}>
              <LockKeyhole size={16} />
              <span>Изход</span>
            </button>
          </div>
        </header>

        {error && (
          <div className="error-banner">
            <AlertTriangle size={18} />
            <span>{error}</span>
          </div>
        )}

        <section className="kpi-grid">
          <Kpi icon={Shield} label="Решения" value={overview.requests_24h} />
          <Kpi icon={Filter} label="Активни правила" value={overview.active_rules} />
          <Kpi icon={AlertTriangle} label="Блокировки" value={overview.blocked_24h} tone="orange" />
          <Kpi icon={ShieldAlert} label="Отворени сигнали" value={overview.open_alerts} tone="red" />
        </section>

        {page}
      </main>
      {infoModal && (
        <div className="modal-backdrop" role="presentation" onClick={() => setInfoModal(null)}>
          <section className={`modal-panel ${infoModal === "project" ? "project-modal" : "license-modal"}`} role="dialog" aria-modal="true" aria-label={infoModal === "project" ? "Проект" : "Лиценз"} onClick={(event) => event.stopPropagation()}>
            <button className="icon-button modal-close" type="button" onClick={() => setInfoModal(null)} title="Затвори">
              <X size={18} />
            </button>
            {infoModal === "project" ? (
              <img className="project-poster" src={publicAssetUrl("/Plakat-Plameli-Digi.jpg")} alt="Проект BG16RFPR001-1.012-0189-C01" />
            ) : (
              <div className="license-content">
                <h2>Лиценз NET Base 03.022<br />03-022-0134</h2>
                <div className="license-table">
                  <div><strong>РАЗРАБОТЧИК</strong><span>Ай-Ти Степ ООД</span></div>
                  <div><strong>Система за Защита</strong><span>NET Base 03.022</span></div>
                  <div><strong>Лиценз</strong><span>03-022-0134</span></div>
                  <div><strong>ЛИЦЕНЗОПОЛУЧАТЕЛ</strong><span>Пламели финанс ЕООД</span></div>
                  <div><strong>Финансирано по проект</strong><span>BG16RFPR001-1.012-0189-C01</span></div>
                </div>
              </div>
            )}
          </section>
        </div>
      )}
    </div>
  );
}

export default App;
