import { useEffect, useState } from "react";
import {
  ArrowDown,
  ArrowUp,
  Check,
  ChevronRight,
  Pencil,
  Play,
  Plus,
  RefreshCw,
  Save,
  Shield,
  Trash2,
} from "lucide-react";
import {
  apiRequest,
  apiPost,
  apiPatch,
  apiDelete,
  formatDate,
  formatNumber,
  StatusBadge,
  Notice,
  DataTable,
  Tabs,
  Panel,
  Drawer,
  Field,
  ConfirmDialog,
  ModuleFrame,
  Toggle,
  SettingsForm,
} from "./ConsoleUI";

const directions = {
  inbound: "Входящ",
  outbound: "Изходящ",
  any: "Двупосочен",
};
const actionsText = {
  allow: "Разреши",
  block: "Блокирай",
  reject: "Отхвърли",
  log: "Запиши и разреши",
  alert: "Сигнал",
  drop: "Блокирано",
  blocked: "Блокирано",
};
const severityOptions = [
  ["critical", "Критична"],
  ["high", "Висока"],
  ["medium", "Средна"],
  ["low", "Ниска"],
  ["informational", "Информация"],
];
const enabledFilter = {
  key: "enabled",
  label: "Статус",
  options: [
    ["true", "Включени"],
    ["false", "Изключени"],
  ],
};
const fwFields = [
  "name",
  "enabled",
  "priority",
  "action",
  "direction",
  "protocol",
  "source_cidr",
  "source_port",
  "destination_cidr",
  "destination_port",
  "description",
];
const pick = (object, keys) =>
  Object.fromEntries(keys.map((key) => [key, object[key]]));
const displayCount = (value) => (value == null ? "—" : formatNumber(value));
const networkAddress = (ip, port) =>
  `${ip || "—"}${port && port !== "any" ? ` · ${port}` : ""}`;

function useChangesGuard(dirty, key) {
  useEffect(() => {
    window.dispatchEvent(
      new CustomEvent("console-dirty", { detail: { key, dirty } }),
    );
    return () =>
      window.dispatchEvent(
        new CustomEvent("console-dirty", { detail: { key, dirty: false } }),
      );
  }, [dirty, key]);
  useEffect(() => {
    if (!dirty) return;
    const warn = (event) => {
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [dirty]);
}

function useOperations(reload) {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState(null);
  const [confirmation, setConfirmation] = useState(null);
  const run = async (operation, success, refresh = true) => {
    if (busy) return;
    setBusy(true);
    setMessage(null);
    try {
      const result = await operation();
      if (result?.ok === false)
        throw new Error(
          result.error || result.message || "Операцията не е изпълнена.",
        );
      if (success)
        setMessage({
          tone: "ok",
          text: typeof success === "function" ? success(result) : success,
        });
      if (refresh) await reload();
      return result ?? true;
    } catch (error) {
      setMessage({ tone: "danger", text: error.message });
      return null;
    } finally {
      setBusy(false);
    }
  };
  const confirm = (title, description, callback) =>
    setConfirmation({ title, description, callback });
  const feedback = (
    <>
      <Notice message={message} onClose={() => setMessage(null)} />
      {confirmation && (
        <ConfirmDialog
          title={confirmation.title}
          description={confirmation.description}
          busy={busy}
          onClose={() => !busy && setConfirmation(null)}
          onConfirm={async () => {
            const next = confirmation;
            setConfirmation(null);
            await next.callback();
          }}
        />
      )}
    </>
  );
  return { busy, message, setMessage, run, confirm, feedback };
}

function DetailGrid({ items }) {
  return (
    <dl className="detail-grid">
      {items.map(([label, value]) => (
        <div key={label}>
          <dt>{label}</dt>
          <dd>{value ?? "—"}</dd>
        </div>
      ))}
    </dl>
  );
}

function RowButton({ title, children, onClick, disabled, danger }) {
  return (
    <button
      type="button"
      className={`icon-button${danger ? " danger" : ""}`}
      aria-label={title}
      title={title}
      disabled={disabled}
      onClick={(event) => {
        event.stopPropagation();
        onClick();
      }}
    >
      {children}
    </button>
  );
}

function RuleEditor({
  initial,
  kind,
  busy,
  message,
  onSave,
  onClose,
  confirm,
}) {
  const [draft, setDraft] = useState(initial);
  const [error, setError] = useState("");
  const dirty = JSON.stringify(draft) !== JSON.stringify(initial);
  useChangesGuard(dirty, "network-editor");
  const update = (key, value) =>
    setDraft((current) => ({ ...current, [key]: value }));
  const close = () => {
    if (busy) return;
    if (dirty)
      confirm(
        "Отхвърляне на промените?",
        "Незапазените промени в това правило ще бъдат загубени.",
        onClose,
      );
    else onClose();
  };
  const submit = async (event) => {
    event.preventDefault();
    setError("");
    if (!draft.name.trim()) {
      setError("Въведете име на правилото.");
      return;
    }
    if (kind === "ips") {
      if (
        !new RegExp(`\\bsid\\s*:\\s*${Number(draft.sid)}\\s*;`).test(
          draft.raw_rule,
        )
      ) {
        setError("SID в сигнатурата трябва да съвпада с полето SID.");
        return;
      }
      if (!draft.raw_rule.trim().endsWith(")")) {
        setError("Сигнатурата трябва да завършва със затваряща скоба.");
        return;
      }
    }
    const payload =
      kind === "firewall"
        ? {
            ...pick(draft, fwFields),
            name: draft.name.trim(),
            priority: Number(draft.priority),
            source_cidr: draft.source_cidr.trim() || "any",
            destination_cidr: draft.destination_cidr.trim() || "any",
            source_port: draft.source_port.trim() || "any",
            destination_port: draft.destination_port.trim() || "any",
          }
        : {
            name: draft.name.trim(),
            sid: Number(draft.sid),
            raw_rule: draft.raw_rule.trim(),
            enabled: draft.enabled,
          };
    const saved = await onSave(payload);
    if (saved) onClose();
  };
  return (
    <Drawer
      title={initial.id ? "Редактиране на правило" : "Ново правило"}
      description={
        kind === "firewall"
          ? "Запазете политиката, след което я приложете към защитната стена."
          : "Потребителска сигнатура за Suricata. SID трябва да е уникален."
      }
      onClose={close}
    >
      <form className="drawer-form" onSubmit={submit}>
        {message?.tone === "danger" && <Notice message={message} />}
        {error && (
          <div className="notice danger" role="alert">
            {error}
          </div>
        )}
        <Field label="Име на правилото">
          <input
            autoFocus
            required
            maxLength={kind === "firewall" ? 140 : 160}
            value={draft.name}
            onChange={(event) => update("name", event.target.value)}
            placeholder={
              kind === "firewall"
                ? "Достъп до административна мрежа"
                : "Откриване на подозрителни SSH връзки"
            }
          />
        </Field>
        <div className="settings-row">
          <div>
            <strong>Включено правило</strong>
            <p className="subtle">
              Изключените правила остават в конфигурацията.
            </p>
          </div>
          <Toggle
            checked={draft.enabled}
            onChange={(value) => update("enabled", value)}
            label="Включено правило"
          />
        </div>
        {kind === "firewall" ? (
          <>
            <div className="form-grid">
              <Field label="Действие">
                <select
                  value={draft.action}
                  onChange={(event) => update("action", event.target.value)}
                >
                  {["allow", "block", "reject", "log"].map((value) => (
                    <option key={value} value={value}>
                      {actionsText[value]}
                    </option>
                  ))}
                </select>
              </Field>
              <Field
                label="Приоритет"
                hint="По-малката стойност се проверява първа."
              >
                <input
                  type="number"
                  required
                  min="0"
                  max="2147483647"
                  value={draft.priority}
                  onChange={(event) => update("priority", event.target.value)}
                />
              </Field>
              <Field label="Посока">
                <select
                  value={draft.direction}
                  onChange={(event) => update("direction", event.target.value)}
                >
                  {Object.entries(directions).map(([key, label]) => (
                    <option key={key} value={key}>
                      {label}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Протокол">
                <select
                  value={draft.protocol}
                  onChange={(event) => {
                    const value = event.target.value;
                    setDraft((current) => ({
                      ...current,
                      protocol: value,
                      ...(!["tcp", "udp"].includes(value)
                        ? { source_port: "any", destination_port: "any" }
                        : {}),
                    }));
                  }}
                >
                  {["any", "tcp", "udp", "icmp"].map((value) => (
                    <option key={value} value={value}>
                      {value === "any"
                        ? "Всички протоколи"
                        : value.toUpperCase()}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Мрежа на източника" hint="IPv4, IPv6, CIDR или any">
                <input
                  required
                  value={draft.source_cidr}
                  maxLength={64}
                  onChange={(event) =>
                    update("source_cidr", event.target.value)
                  }
                  placeholder="10.20.0.0/16"
                />
              </Field>
              <Field label="Порт на източника" hint="1–65535 или any">
                <input
                  disabled={!["tcp", "udp"].includes(draft.protocol)}
                  value={draft.source_port}
                  pattern="([Aa][Nn][Yy]|\*|[0-9]{1,5})"
                  onChange={(event) =>
                    update("source_port", event.target.value)
                  }
                />
              </Field>
              <Field
                label="Мрежа на дестинацията"
                hint="IPv4, IPv6, CIDR или any"
              >
                <input
                  required
                  value={draft.destination_cidr}
                  maxLength={64}
                  onChange={(event) =>
                    update("destination_cidr", event.target.value)
                  }
                  placeholder="10.30.0.0/16"
                />
              </Field>
              <Field label="Порт на дестинацията" hint="1–65535 или any">
                <input
                  disabled={!["tcp", "udp"].includes(draft.protocol)}
                  value={draft.destination_port}
                  pattern="([Aa][Nn][Yy]|\*|[0-9]{1,5})"
                  onChange={(event) =>
                    update("destination_port", event.target.value)
                  }
                />
              </Field>
            </div>
            <Field label="Описание">
              <textarea
                value={draft.description}
                rows={3}
                onChange={(event) => update("description", event.target.value)}
                placeholder="Предназначение, отговорен екип или номер на заявка"
              />
            </Field>
          </>
        ) : (
          <>
            <Field
              label="Идентификатор на сигнатурата (SID)"
              hint="Използвайте уникална стойност от 1000000 нагоре."
            >
              <input
                type="number"
                min="1000000"
                max="2147483647"
                required
                value={draft.sid}
                onChange={(event) => update("sid", event.target.value)}
              />
            </Field>
            <Field
              label="Сигнатура Suricata"
              hint="SID в сигнатурата трябва да съвпада с идентификатора по-горе."
            >
              <textarea
                className="mono"
                required
                rows={7}
                spellCheck={false}
                value={draft.raw_rule}
                onChange={(event) => update("raw_rule", event.target.value)}
              />
            </Field>
            {initial.validation_error && (
              <div className="notice warn">
                Последна проверка: {initial.validation_error}
              </div>
            )}
            <p className="subtle">
              Записът проверява формата на правилото. Използвайте „Провери
              конфигурацията“ за проверка със Suricata.
            </p>
          </>
        )}
        <div className="form-footer">
          <button
            type="button"
            className="secondary"
            onClick={close}
            disabled={busy}
          >
            Отказ
          </button>
          <button
            type="submit"
            className="primary"
            disabled={busy || (Boolean(initial.id) && !dirty)}
          >
            <Save size={16} />
            {busy ? "Запазване…" : "Запази правило"}
          </button>
        </div>
      </form>
    </Drawer>
  );
}

function FirewallSimulation() {
  const [draft, setDraft] = useState({
    source_ip: "",
    destination_ip: "",
    source_port: "",
    destination_port: "443",
    direction: "outbound",
    protocol: "tcp",
  });
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const update = (key, value) => {
    setDraft((current) => ({ ...current, [key]: value }));
    setResult(null);
    setError("");
  };
  const submit = async (event) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    setResult(null);
    try {
      setResult(
        await apiPost("/firewall/evaluate/", {
          ...draft,
          destination: draft.destination_ip,
        }),
      );
    } catch (current) {
      setError(current.message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Panel
      title="Проверка на връзка"
      description="Оценка на запазените правила по приоритет. Не изпраща трафик и не създава събитие."
    >
      <form className="drawer-form" onSubmit={submit}>
        <div className="form-grid">
          <Field label="IP на източника">
            <input
              required
              value={draft.source_ip}
              onChange={(event) => update("source_ip", event.target.value)}
              placeholder="192.168.10.25"
            />
          </Field>
          <Field label="IP на дестинацията">
            <input
              required
              value={draft.destination_ip}
              onChange={(event) => update("destination_ip", event.target.value)}
              placeholder="10.20.0.10"
            />
          </Field>
          <Field label="Протокол">
            <select
              value={draft.protocol}
              onChange={(event) => {
                const value = event.target.value;
                setDraft((current) => ({
                  ...current,
                  protocol: value,
                  ...(value === "icmp"
                    ? { source_port: "", destination_port: "" }
                    : {}),
                }));
                setResult(null);
              }}
            >
              {["tcp", "udp", "icmp"].map((value) => (
                <option key={value} value={value}>
                  {value.toUpperCase()}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Посока">
            <select
              value={draft.direction}
              onChange={(event) => update("direction", event.target.value)}
            >
              <option value="inbound">Входящ</option>
              <option value="outbound">Изходящ</option>
            </select>
          </Field>
          <Field label="Порт на източника" hint="Незадължителен">
            <input
              type="number"
              min="1"
              max="65535"
              disabled={draft.protocol === "icmp"}
              value={draft.source_port}
              onChange={(event) => update("source_port", event.target.value)}
              placeholder="52000"
            />
          </Field>
          <Field label="Порт на дестинацията">
            <input
              type="number"
              min="1"
              max="65535"
              disabled={draft.protocol === "icmp"}
              required={draft.protocol !== "icmp"}
              value={draft.destination_port}
              onChange={(event) =>
                update("destination_port", event.target.value)
              }
            />
          </Field>
        </div>
        {error && (
          <div className="notice danger" role="alert">
            {error}
          </div>
        )}
        <div className="form-footer">
          <button className="primary" disabled={busy}>
            <Play size={15} />
            {busy ? "Проверка…" : "Провери връзката"}
          </button>
        </div>
      </form>
      {result && (
        <div className="result-card" aria-live="polite">
          <div className="panel-heading">
            <h3>Решение по запазената политика</h3>
            <StatusBadge
              value={result.policy_action || result.action}
              label={
                actionsText[result.policy_action || result.action] ||
                result.action
              }
            />
          </div>
          <DetailGrid
            items={[
              [
                "Съвпадащо правило",
                result.matched_rule?.name ||
                  "Няма съвпадение — действие по подразбиране",
              ],
              ["Приоритет", result.matched_rule?.priority ?? "—"],
              [
                "Действие по подразбиране",
                actionsText[result.default_action] || result.default_action,
              ],
              [
                "Режим на оценката",
                result.module_enabled === false || result.mode === "disabled"
                  ? "Изключен"
                  : result.mode === "monitor"
                    ? "Наблюдение"
                    : "Прилагане",
              ],
              [
                "Ефективно решение на API",
                actionsText[result.action] || result.action,
              ],
            ]}
          />
          <p className="subtle">
            Проверката използва запазената политика. Режимите „Наблюдение“ и
            „Изключен“ разрешават заявката в API оценката. Приложената
            конфигурация на nftables се управлява отделно.
          </p>
        </div>
      )}
    </Panel>
  );
}

export function FirewallWorkspace({ data, actions }) {
  const [tab, setTab] = useState("rules");
  const [editor, setEditor] = useState(null);
  const [selected, setSelected] = useState(null);
  const op = useOperations(actions.reload);
  const status = data.firewallStatus || {};
  const setting = (data.settings || []).find((item) => item.key === "firewall");
  const rules = [...(data.firewallRules || [])].sort(
    (a, b) => a.priority - b.priority || a.id - b.id,
  );
  const events = (data.firewallEvents || []).map((row) => ({
    ...row,
    action: row.extra_data?.action || "",
    protocol: row.extra_data?.protocol || "",
    rule_name: row.extra_data?.matched_rule_name || "",
  }));
  const pending = Boolean(status.has_unapplied_changes);
  const create = () =>
    setEditor({
      name: "",
      enabled: true,
      priority: Math.min(
        2147483647,
        Math.max(0, ...rules.map((row) => row.priority)) + 10,
      ),
      action: "block",
      direction: "inbound",
      protocol: "tcp",
      source_cidr: "any",
      source_port: "any",
      destination_cidr: "any",
      destination_port: "any",
      description: "",
    });
  const apply = async (override = false) => {
    await op.run(
      async () => {
        const result = await apiPost("/firewall/apply/", {
          confirm_admin_lockout: override,
        });
        if (result.warning && !override) {
          op.confirm(
            "Възможна загуба на административен достъп",
            `${result.warning}. Потвърдете само ако имате алтернативен достъп до сървъра.`,
            () => apply(true),
          );
          return { deferred: true };
        }
        return result;
      },
      (result) =>
        result.deferred
          ? "Прилагането чака потвърждение за административния достъп."
          : "Конфигурацията е приложена към nftables.",
    );
  };
  const rulesColumns = [
    {
      key: "priority",
      label: "Ред",
      render: (row) => <span className="mono">{row.priority}</span>,
    },
    {
      key: "name",
      label: "Правило",
      searchValue: (row) => `${row.name} ${row.description || ""}`,
      exportValue: (row) =>
        `${row.name}${row.description ? ` · ${row.description}` : ""}`,
      render: (row) => (
        <>
          <span className="cell-title">{row.name}</span>
          <span className="cell-subtitle">
            {row.description || `ID ${row.id}`}{" "}
            {row.apply_error ? "· Грешка при прилагане" : ""}
          </span>
        </>
      ),
    },
    {
      key: "enabled",
      label: "Статус",
      render: (row) => (
        <Toggle
          checked={row.enabled}
          disabled={op.busy}
          label={`${row.enabled ? "Изключи" : "Включи"} ${row.name}`}
          onChange={() =>
            op.run(
              () =>
                apiPost(
                  `/firewall/rules/${row.id}/${row.enabled ? "disable" : "enable"}/`,
                  {},
                ),
              "Статусът е запазен. Приложете правилата, за да обновите nftables.",
            )
          }
        />
      ),
    },
    {
      key: "source_cidr",
      label: "Източник",
      searchValue: (row) => `${row.source_cidr} ${row.source_port}`,
      exportValue: (row) => `${row.source_cidr} · ${row.source_port}`,
      render: (row) => (
        <>
          <span className="mono cell-title">{row.source_cidr || "any"}</span>
          <span className="cell-subtitle">Порт {row.source_port || "any"}</span>
        </>
      ),
    },
    {
      key: "destination_cidr",
      label: "Дестинация",
      searchValue: (row) => `${row.destination_cidr} ${row.destination_port}`,
      exportValue: (row) => `${row.destination_cidr} · ${row.destination_port}`,
      render: (row) => (
        <>
          <span className="mono cell-title">
            {row.destination_cidr || "any"}
          </span>
          <span className="cell-subtitle">
            Порт {row.destination_port || "any"}
          </span>
        </>
      ),
    },
    {
      key: "protocol",
      label: "Трафик",
      render: (row) => (
        <>
          <span className="cell-title">{row.protocol.toUpperCase()}</span>
          <span className="cell-subtitle">{directions[row.direction]}</span>
        </>
      ),
    },
    {
      key: "action",
      label: "Действие",
      render: (row) => (
        <StatusBadge value={row.action} label={actionsText[row.action]} />
      ),
    },
    {
      key: "operations",
      label: "Операции",
      render: (row) => (
        <div className="row-actions">
          <RowButton
            title="Премести нагоре"
            disabled={op.busy || rules[0]?.id === row.id}
            onClick={() =>
              op.run(
                () => apiPost(`/firewall/rules/${row.id}/move-up/`, {}),
                "Приоритетите са запазени. Приложете правилата.",
              )
            }
          >
            <ArrowUp size={14} />
          </RowButton>
          <RowButton
            title="Премести надолу"
            disabled={op.busy || rules.at(-1)?.id === row.id}
            onClick={() =>
              op.run(
                () => apiPost(`/firewall/rules/${row.id}/move-down/`, {}),
                "Приоритетите са запазени. Приложете правилата.",
              )
            }
          >
            <ArrowDown size={14} />
          </RowButton>
          <RowButton
            title={`Редактирай ${row.name}`}
            disabled={op.busy}
            onClick={() =>
              setEditor({
                ...row,
                source_port: row.source_port || "any",
                destination_port: row.destination_port || "any",
              })
            }
          >
            <Pencil size={15} />
          </RowButton>
          <RowButton
            title={`Изтрий ${row.name}`}
            danger
            disabled={op.busy}
            onClick={() =>
              op.confirm(
                "Изтриване на правило?",
                `„${row.name}“ ще бъде премахнато от запазената политика. Промяната влиза в сила след прилагане.`,
                () =>
                  op.run(
                    () => apiDelete(`/firewall/rules/${row.id}/`),
                    "Правилото е изтрито. Приложете конфигурацията, за да обновите nftables.",
                  ),
              )
            }
          >
            <Trash2 size={15} />
          </RowButton>
        </div>
      ),
    },
  ];
  return (
    <ModuleFrame
      eyebrow="МРЕЖОВА СИГУРНОСТ"
      title="Защитна стена"
      description="Контрол на входящия и изходящия трафик с подредени мрежови политики."
      status={
        <StatusBadge
          value={
            pending || status.runtime_available === false
              ? "warning"
              : "neutral"
          }
          label={
            status.runtime_available === false
              ? "nftables не е наличен"
              : pending
                ? "Неприложени промени"
                : status.last_apply
                  ? "Конфигурация приложена"
                  : "Не е прилагана"
          }
        />
      }
      actions={
        <>
          <button className="secondary" onClick={create} disabled={op.busy}>
            <Plus size={16} />
            Ново правило
          </button>
          <button
            className="primary"
            disabled={
              op.busy ||
              !data.firewallStatus ||
              status.runtime_available === false
            }
            onClick={() =>
              op.confirm(
                "Прилагане на мрежовата политика",
                `Ще бъдат приложени ${rules.filter((row) => row.enabled).length} включени правила към nftables. Промяната може да засегне активни връзки.`,
                () => apply(),
              )
            }
          >
            <Shield size={16} />
            {op.busy ? "Изпълнение…" : "Приложи правилата"}
          </button>
        </>
      }
      metrics={[
        {
          label: "Включени правила",
          value: rules.filter((row) => row.enabled).length,
          hint: `${rules.length} общо в политиката`,
        },
        {
          label: "Блокирани връзки",
          value: displayCount(status.blocked_24h),
          hint: "Регистрирани за последните 24 часа",
          tone: "orange",
        },
        {
          label: "Последно прилагане",
          value: formatDate(status.last_apply),
          hint: status.backend || "nftables",
        },
        {
          label: "Последна промяна",
          value: formatDate(status.last_rule_update),
          hint: pending ? "Изисква прилагане" : "Запазена конфигурация",
        },
      ]}
    >
      {op.feedback}
      {status.runtime_available === false && (
        <div className="notice warn">
          nftables не е наличен в средата на сървъра. Можете да подготвяте
          правила и да проверявате политиката; прилагането изисква настроен
          nftables.
        </div>
      )}
      {status.enabled === false && (
        <div className="notice warn">
          Модулът е изключен в запазената конфигурация. Прилагането ще премахне
          управляваните правила от nftables.
        </div>
      )}
      <Tabs
        value={tab}
        onChange={setTab}
        items={[
          { key: "rules", label: "Правила", count: rules.length },
          { key: "events", label: "Събития", count: events.length },
          { key: "test", label: "Провери връзка" },
          { key: "settings", label: "Настройки" },
        ]}
      />
      {tab === "rules" && (
        <Panel
          title="Мрежова политика"
          description="Първото съвпадащо правило определя действието. Промените се запазват преди прилагане."
        >
          <DataTable
            rows={rules}
            columns={rulesColumns}
            searchPlaceholder="Търси име, IP адрес или описание…"
            filters={[
              enabledFilter,
              {
                key: "action",
                label: "Действие",
                options: Object.entries(actionsText).filter(([key]) =>
                  ["allow", "block", "reject", "log"].includes(key),
                ),
              },
              {
                key: "direction",
                label: "Посока",
                options: Object.entries(directions),
              },
            ]}
            exportName="firewall-rules"
            emptyTitle="Няма конфигурирани правила"
            emptyDescription="Добавете първото правило с бутона „Ново правило“."
          />
        </Panel>
      )}
      {tab === "events" && (
        <Panel
          title="Журнал на мрежовите решения"
          description="Последните 100 получени събития. Изберете запис за всички детайли."
        >
          <DataTable
            rows={events}
            onRowClick={setSelected}
            exportName="firewall-events"
            searchPlaceholder="Търси IP, правило или събитие…"
            filters={[
              {
                key: "action",
                label: "Действие",
                options: [
                  ["allow", "Разрешено"],
                  ["block", "Блокирано"],
                  ["reject", "Отхвърлено"],
                  ["log", "Записано"],
                ],
              },
            ]}
            emptyTitle="Няма получени събития"
            emptyDescription="Събитията ще се появят след подаване на данни от защитната стена."
            columns={[
              {
                key: "occurred_at",
                label: "Време",
                render: (row) => formatDate(row.occurred_at),
              },
              {
                key: "source_ip",
                label: "Източник",
                render: (row) => (
                  <span className="mono">
                    {networkAddress(row.source_ip, row.extra_data?.source_port)}
                  </span>
                ),
              },
              {
                key: "destination",
                label: "Дестинация",
                render: (row) => (
                  <span className="mono">
                    {networkAddress(
                      row.destination || row.extra_data?.destination_ip,
                      row.extra_data?.destination_port,
                    )}
                  </span>
                ),
              },
              {
                key: "protocol",
                label: "Протокол",
                render: (row) => row.protocol.toUpperCase() || "—",
              },
              {
                key: "rule_name",
                label: "Правило",
                render: (row) => row.rule_name || "По подразбиране",
              },
              {
                key: "action",
                label: "Решение",
                render: (row) => (
                  <StatusBadge
                    value={row.action}
                    label={
                      actionsText[row.action] || row.action || "Неизвестно"
                    }
                  />
                ),
              },
            ]}
          />
        </Panel>
      )}
      {tab === "test" && <FirewallSimulation />}
      <div hidden={tab !== "settings"}>
        <div className="console-stack">
          <SettingsForm
            setting={setting}
            moduleKey="firewall"
            onSave={actions.saveSetting}
          />
          <Panel title="Среда на изпълнение">
            <DetailGrid
              items={[
                ["Механизъм", status.backend || "nftables"],
                [
                  "Наличност",
                  status.runtime_available == null
                    ? "Няма данни"
                    : status.runtime_available
                      ? "Пакетът е наличен"
                      : "Пакетът не е наличен",
                ],
                ["Управлявана таблица", status.table || "—"],
                ["Последно прилагане", formatDate(status.last_apply)],
                ["Неприложени промени", pending ? "Да" : "Не"],
              ]}
            />
            <p className="subtle">
              Датата на прилагане потвърждава последния успешен запис на
              конфигурация. Тя не е проверка за текущото състояние на услугата.
            </p>
          </Panel>
        </div>
      </div>
      {editor && (
        <RuleEditor
          initial={editor}
          kind="firewall"
          busy={op.busy}
          message={op.message}
          confirm={op.confirm}
          onClose={() => setEditor(null)}
          onSave={(payload) =>
            op.run(
              () =>
                editor.id
                  ? apiPatch(`/firewall/rules/${editor.id}/`, payload)
                  : apiPost("/firewall/rules/", payload),
              "Правилото е запазено. Приложете правилата, за да обновите nftables.",
            )
          }
        />
      )}
      {selected && (
        <Drawer
          title="Детайли на мрежово събитие"
          description={`Събитие #${selected.id} · ${formatDate(selected.occurred_at)}`}
          onClose={() => setSelected(null)}
        >
          <DetailGrid
            items={[
              [
                "Източник",
                networkAddress(
                  selected.source_ip,
                  selected.extra_data?.source_port,
                ),
              ],
              [
                "Дестинация",
                networkAddress(
                  selected.destination,
                  selected.extra_data?.destination_port,
                ),
              ],
              ["Протокол", selected.protocol.toUpperCase() || "—"],
              ["Посока", directions[selected.extra_data?.direction] || "—"],
              [
                "Решение",
                <StatusBadge
                  value={selected.action}
                  label={
                    actionsText[selected.action] ||
                    selected.action ||
                    "Неизвестно"
                  }
                />,
              ],
              ["Правило", selected.rule_name || "По подразбиране"],
            ]}
          />
          <p>{selected.message}</p>
          <details className="technical-details">
            <summary>Технически данни</summary>
            <pre className="code-block">
              {JSON.stringify(selected.extra_data || {}, null, 2)}
            </pre>
          </details>
        </Drawer>
      )}
    </ModuleFrame>
  );
}

const toIpsDraft = (setting) => ({
  enabled: setting?.enabled ?? true,
  mode: setting?.settings?.mode || "ids",
  interface: setting?.settings?.interface || "",
  home_net: setting?.settings?.home_net || "",
  logging_enabled: setting?.settings?.logging_enabled ?? true,
});

function IpsSettings({ setting, interfaces, op }) {
  const [draft, setDraft] = useState(() => toIpsDraft(setting));
  const [baseline, setBaseline] = useState(() => toIpsDraft(setting));
  const dirty = JSON.stringify(draft) !== JSON.stringify(baseline);
  useChangesGuard(dirty, "network-settings");
  useEffect(() => {
    if (!dirty) {
      const value = toIpsDraft(setting);
      setDraft(value);
      setBaseline(value);
    }
  }, [setting?.updated_at]);
  const update = (key, value) =>
    setDraft((current) => ({ ...current, [key]: value }));
  const save = async () => {
    const result = await op.run(
      () =>
        apiRequest("/ips/settings/", {
          method: "PUT",
          body: JSON.stringify(draft),
        }),
      "Настройките са запазени. Проверете конфигурацията преди внедряване в Suricata.",
    );
    if (result) {
      const current = toIpsDraft(result);
      setDraft(current);
      setBaseline(current);
    }
  };
  return (
    <Panel
      title="Настройки на Suricata"
      description="Конфигурационен профил за внедряване. Записът не стартира и не променя работещия процес."
    >
      <form
        className="drawer-form"
        onSubmit={(event) => {
          event.preventDefault();
          if (draft.mode === "ips" && baseline.mode !== "ips")
            op.confirm(
              "Профил за режим IPS",
              "Запазвате профил за блокиране на трафик. За да влезе в сила, Suricata трябва да бъде конфигурирана и внедрена от администратор.",
              save,
            );
          else save();
        }}
      >
        <div className="settings-row">
          <div>
            <strong>Профилът е включен</strong>
            <p className="subtle">
              Отразява желаното състояние, не състоянието на процеса.
            </p>
          </div>
          <Toggle
            checked={draft.enabled}
            label="Включен IPS профил"
            onChange={(value) => update("enabled", value)}
          />
        </div>
        <div className="form-grid">
          <Field label="Режим на профила">
            <select
              value={draft.mode}
              onChange={(event) => update("mode", event.target.value)}
            >
              <option value="ids">IDS · откриване</option>
              <option value="ips">IPS · откриване и блокиране</option>
            </select>
          </Field>
          <Field label="Мрежов интерфейс">
            <select
              value={draft.interface}
              onChange={(event) => update("interface", event.target.value)}
            >
              <option value="">Автоматичен избор</option>
              {draft.interface && !interfaces.includes(draft.interface) && (
                <option value={draft.interface}>
                  {draft.interface} (недостъпен)
                </option>
              )}
              {interfaces.map((name) => (
                <option key={name} value={name}>
                  {name}
                </option>
              ))}
            </select>
          </Field>
        </div>
        <Field
          label="Защитени мрежи · HOME_NET"
          hint="Една или повече IPv4/IPv6 мрежи, разделени със запетая."
        >
          <textarea
            rows={3}
            required
            value={draft.home_net}
            onChange={(event) => update("home_net", event.target.value)}
            placeholder="192.168.1.0/24, 10.0.0.0/8"
          />
        </Field>
        <div className="settings-row">
          <div>
            <strong>Запис на събития в профила</strong>
            <p className="subtle">
              Прилага се при конфигуриране на EVE изхода в Suricata.
            </p>
          </div>
          <Toggle
            checked={draft.logging_enabled}
            label="Запис на събития в профила"
            onChange={(value) => update("logging_enabled", value)}
          />
        </div>
        <div className="form-footer">
          <span className="subtle">
            {dirty
              ? "Има незапазени промени"
              : `Последно запазване: ${formatDate(setting?.updated_at)}`}
          </span>
          <button
            type="button"
            className="secondary"
            disabled={!dirty || op.busy}
            onClick={() =>
              op.confirm(
                "Отхвърляне на промените?",
                "Профилът ще бъде върнат към последните запазени стойности.",
                () => setDraft(baseline),
              )
            }
          >
            Възстанови
          </button>
          <button className="primary" disabled={!dirty || op.busy || !setting}>
            <Save size={16} />
            {op.busy ? "Запазване…" : "Запази профила"}
          </button>
        </div>
      </form>
    </Panel>
  );
}

export function IPSWorkspace({ data, actions }) {
  const [tab, setTab] = useState("overview");
  const [editor, setEditor] = useState(null);
  const [selected, setSelected] = useState(null);
  const op = useOperations(actions.reload);
  const status = data.ipsStatus || {};
  const setting = data.ipsSettings;
  const events = data.ipsEvents || [];
  const rules = data.ipsCustomRules || [];
  const categories = data.ipsCategories || [];
  const available = status.service_status === "available";
  const serviceLabel =
    status.service_status === "not_installed"
      ? "Suricata не е инсталирана"
      : available
        ? "Suricata е налична"
        : status.service_status === "error"
          ? "Грешка в Suricata"
          : "Състоянието е неизвестно";
  const create = () => {
    const sid = Math.max(1000000, ...rules.map((row) => row.sid)) + 1;
    setEditor({
      name: "",
      sid,
      raw_rule: `alert tcp any any -> $HOME_NET 22 (msg:"SSH connection"; sid:${sid}; rev:1;)`,
      enabled: true,
    });
  };
  const validate = () =>
    op.confirm(
      "Проверка на конфигурацията",
      "Включените потребителски сигнатури ще бъдат записани и проверени със Suricata. Действието не рестартира услугата и не включва блокиране на трафик.",
      () =>
        op.run(
          () => apiPost("/ips/apply/", {}),
          "Конфигурацията премина проверката на Suricata. Внедряването се извършва от администратор.",
        ),
    );
  const eventColumns = [
    {
      key: "timestamp",
      label: "Време",
      render: (row) => formatDate(row.timestamp),
    },
    {
      key: "severity",
      label: "Важност",
      sortValue: (row) =>
        ({ informational: 0, low: 1, medium: 2, high: 3, critical: 4 })[
          row.severity
        ],
      render: (row) => <StatusBadge value={row.severity} />,
    },
    {
      key: "signature",
      label: "Сигнатура",
      searchValue: (row) =>
        `${row.signature} ${row.category} ${row.signature_id}`,
      exportValue: (row) =>
        `${row.signature} · ${row.category} · SID ${row.signature_id || ""}`,
      render: (row) => (
        <>
          <span className="cell-title">{row.signature}</span>
          <span className="cell-subtitle">
            {row.category || "Без категория"} · SID {row.signature_id || "—"}
          </span>
        </>
      ),
    },
    {
      key: "source_ip",
      label: "Източник",
      render: (row) => (
        <span className="mono">
          {networkAddress(row.source_ip, row.source_port)}
        </span>
      ),
    },
    {
      key: "destination_ip",
      label: "Дестинация",
      render: (row) => (
        <span className="mono">
          {networkAddress(row.destination_ip, row.destination_port)}
        </span>
      ),
    },
    {
      key: "action",
      label: "Действие",
      render: (row) => (
        <StatusBadge
          value={row.action}
          label={actionsText[row.action] || row.action}
        />
      ),
    },
  ];
  const eventTable = (rows, overview = false) => (
    <DataTable
      rows={rows}
      columns={eventColumns}
      onRowClick={setSelected}
      pageSize={overview ? 5 : 10}
      searchPlaceholder="Търси сигнатура, IP, категория…"
      exportName={overview ? undefined : "ips-events"}
      filters={
        overview
          ? []
          : [
              { key: "severity", label: "Важност", options: severityOptions },
              {
                key: "action",
                label: "Действие",
                options: [...new Set(events.map((row) => row.action))].map(
                  (value) => [value, actionsText[value] || value],
                ),
              },
              {
                key: "protocol",
                label: "Протокол",
                options: [
                  ...new Set(events.map((row) => row.protocol).filter(Boolean)),
                ].map((value) => [value, value.toUpperCase()]),
              },
            ]
      }
      emptyTitle="Няма получени сигнали"
      emptyDescription="Сигналите се зареждат от Suricata EVE. Липсата на записи не потвърждава, че инспекцията е активна."
    />
  );
  return (
    <ModuleFrame
      eyebrow="ОТКРИВАНЕ И АНАЛИЗ"
      title="Откриване на прониквания"
      description="Анализ на сигнали, управление на сигнатури и конфигурационни профили за Suricata."
      status={
        <StatusBadge
          value={available ? "neutral" : "warning"}
          label={serviceLabel}
        />
      }
      actions={
        <>
          <button
            className="secondary"
            disabled={op.busy}
            onClick={() =>
              op.confirm(
                "Обновяване на сигнатурите",
                "Ще бъде изпълнено suricata-update за изтегляне на актуални правила. Операцията може да отнеме до две минути.",
                () =>
                  op.run(
                    () =>
                      apiRequest("/ips/update-rules/", {
                        method: "POST",
                        body: "{}",
                        timeoutMs: 150000,
                      }),
                    "Обновяването на сигнатурите завърши успешно.",
                  ),
              )
            }
          >
            <RefreshCw size={16} />
            Обнови сигнатурите
          </button>
          <button className="primary" onClick={validate} disabled={op.busy}>
            <Check size={16} />
            {op.busy ? "Изпълнение…" : "Провери конфигурацията"}
          </button>
        </>
      }
      metrics={[
        {
          label: "Сигнали за 24 часа",
          value: displayCount(status.alerts_24h),
          hint: "Получени от Suricata EVE",
        },
        {
          label: "Висока важност",
          value: displayCount(status.high_severity),
          hint: "Високи и критични за 24 часа",
          tone: "red",
        },
        {
          label: "Блокирани събития",
          value: displayCount(status.blocked_24h),
          hint: "Докладвани от Suricata за 24 часа",
          tone: "orange",
        },
        {
          label: "Включени сигнатури",
          value: displayCount(status.rules_enabled),
          hint: "Според запазената конфигурация",
        },
      ]}
    >
      {op.feedback}
      <Tabs
        value={tab}
        onChange={setTab}
        items={[
          { key: "overview", label: "Преглед" },
          { key: "events", label: "Събития", count: events.length },
          { key: "rules", label: "Сигнатури", count: rules.length },
          { key: "settings", label: "Настройки" },
        ]}
      />
      {tab === "overview" && (
        <div className="console-stack">
          <Panel
            title="Оперативно състояние"
            description="Наличността на Suricata и получаването на събития се наблюдават отделно."
          >
            <DetailGrid
              items={[
                ["Конфигурационен режим", (status.mode || "ids").toUpperCase()],
                ["Състояние на пакета", serviceLabel],
                ["Последно получено събитие", formatDate(status.last_event)],
                [
                  "Интерфейс на профила",
                  setting?.settings?.interface || "Автоматичен избор",
                ],
                [
                  "Защитени мрежи",
                  setting?.settings?.home_net || "Не са зададени",
                ],
                ["Версия", status.version || "Няма данни"],
              ]}
            />
            <div className="notice info">
              Панелът управлява профили и проверява сигнатури. Стартирането на
              процеса, inline режимът и внедряването на конфигурацията се
              извършват в средата на Suricata.
            </div>
            {status.service_message && (
              <p className="subtle">{status.service_message}</p>
            )}
          </Panel>
          <Panel
            title="Последни сигнали"
            actions={
              <button className="secondary" onClick={() => setTab("events")}>
                Всички събития
                <ChevronRight size={15} />
              </button>
            }
          >
            {eventTable(events.slice(0, 5), true)}
          </Panel>
        </div>
      )}
      {tab === "events" && (
        <Panel
          title="Журнал на сигурността"
          description="Последните 1000 получени събития. Изберете сигнал за разследване и детайли."
        >
          {eventTable(events)}
        </Panel>
      )}
      {tab === "rules" && (
        <div className="console-stack">
          <Panel
            title="Категории сигнатури"
            description="Запазен избор на категории. Синхронизирайте избора с активния набор при внедряване на Suricata."
          >
            <DataTable
              rows={categories}
              exportName="ips-categories"
              searchPlaceholder="Търси категория…"
              filters={[enabledFilter]}
              emptyTitle="Няма категории"
              columns={[
                {
                  key: "name",
                  label: "Категория",
                  render: (row) => (
                    <>
                      <span className="cell-title">{row.name}</span>
                      <span className="cell-subtitle">
                        {row.description || "Набор от сигнатури"}
                      </span>
                    </>
                  ),
                },
                {
                  key: "rule_count",
                  label: "Сигнатури",
                  render: (row) => formatNumber(row.rule_count),
                },
                {
                  key: "updated_at",
                  label: "Последна промяна",
                  render: (row) => formatDate(row.updated_at),
                },
                {
                  key: "enabled",
                  label: "Включена в профила",
                  render: (row) => (
                    <Toggle
                      checked={row.enabled}
                      disabled={op.busy}
                      label={`${row.enabled ? "Изключи" : "Включи"} категория ${row.name}`}
                      onChange={() =>
                        op.run(
                          () =>
                            apiPatch(`/ips/rule-categories/${row.id}/`, {
                              enabled: !row.enabled,
                            }),
                          "Изборът на категории е запазен за следващото внедряване.",
                        )
                      }
                    />
                  ),
                },
              ]}
            />
          </Panel>
          <Panel
            title="Потребителски сигнатури"
            description="Собствени правила с уникален SID, проверка на формата и контрол на състоянието."
            actions={
              <button className="primary" disabled={op.busy} onClick={create}>
                <Plus size={16} />
                Нова сигнатура
              </button>
            }
          >
            <DataTable
              rows={rules}
              searchPlaceholder="Търси име, SID или съдържание…"
              exportName="ips-custom-rules"
              filters={[enabledFilter]}
              emptyTitle="Няма потребителски сигнатури"
              emptyDescription="Добавете правило за специфичен за вашата среда трафик."
              columns={[
                {
                  key: "sid",
                  label: "SID",
                  render: (row) => <span className="mono">{row.sid}</span>,
                },
                {
                  key: "name",
                  label: "Сигнатура",
                  searchValue: (row) => `${row.name} ${row.raw_rule}`,
                  render: (row) => (
                    <>
                      <span className="cell-title">{row.name}</span>
                      <span className="cell-subtitle">
                        Променена {formatDate(row.updated_at)}
                      </span>
                    </>
                  ),
                },
                {
                  key: "enabled",
                  label: "Включена",
                  render: (row) => (
                    <Toggle
                      checked={row.enabled}
                      disabled={op.busy}
                      label={`${row.enabled ? "Изключи" : "Включи"} ${row.name}`}
                      onChange={() =>
                        op.run(
                          () =>
                            apiPatch(`/ips/custom-rules/${row.id}/`, {
                              enabled: !row.enabled,
                            }),
                          "Статусът е запазен. Проверете конфигурацията преди внедряване.",
                        )
                      }
                    />
                  ),
                },
                {
                  key: "validation_error",
                  label: "Проверка",
                  render: (row) => (
                    <>
                      <StatusBadge
                        value={row.validation_error ? "warning" : "neutral"}
                        label={
                          row.validation_error
                            ? "Невалидна"
                            : row.applied_at
                              ? "Проверена със Suricata"
                              : "Форматът е приет"
                        }
                      />
                      <span className="cell-subtitle">
                        {row.validation_error ||
                          (row.applied_at
                            ? formatDate(row.applied_at)
                            : "Очаква проверка със Suricata")}
                      </span>
                    </>
                  ),
                },
                {
                  key: "operations",
                  label: "Операции",
                  render: (row) => (
                    <div className="row-actions">
                      <RowButton
                        title={`Редактирай ${row.name}`}
                        disabled={op.busy}
                        onClick={() => setEditor(row)}
                      >
                        <Pencil size={15} />
                      </RowButton>
                      <RowButton
                        title={`Изтрий ${row.name}`}
                        danger
                        disabled={op.busy}
                        onClick={() =>
                          op.confirm(
                            "Изтриване на сигнатура?",
                            `„${row.name}“ (SID ${row.sid}) ще бъде премахната от запазения набор.`,
                            () =>
                              op.run(
                                () => apiDelete(`/ips/custom-rules/${row.id}/`),
                                "Сигнатурата е изтрита. Проверете новия набор преди внедряване.",
                              ),
                          )
                        }
                      >
                        <Trash2 size={15} />
                      </RowButton>
                    </div>
                  ),
                },
              ]}
            />
          </Panel>
        </div>
      )}
      <div hidden={tab !== "settings"}>
        <IpsSettings
          setting={setting}
          interfaces={status.interfaces || setting?.interfaces || []}
          op={op}
        />
      </div>
      {editor && (
        <RuleEditor
          initial={editor}
          kind="ips"
          busy={op.busy}
          message={op.message}
          confirm={op.confirm}
          onClose={() => setEditor(null)}
          onSave={(payload) =>
            op.run(
              () =>
                editor.id
                  ? apiPatch(`/ips/custom-rules/${editor.id}/`, payload)
                  : apiPost("/ips/custom-rules/", payload),
              (result) =>
                result.validation_error
                  ? `Записано с грешка: ${result.validation_error}`
                  : "Сигнатурата е запазена. Проверете конфигурацията преди внедряване.",
            )
          }
        />
      )}
      {selected && (
        <Drawer
          title={selected.signature}
          description={`SID ${selected.signature_id || "—"} · Събитие #${selected.id}`}
          onClose={() => setSelected(null)}
        >
          <DetailGrid
            items={[
              ["Време", formatDate(selected.timestamp)],
              ["Важност", <StatusBadge value={selected.severity} />],
              ["Категория", selected.category || "—"],
              [
                "Действие",
                <StatusBadge
                  value={selected.action}
                  label={actionsText[selected.action] || selected.action}
                />,
              ],
              [
                "Източник",
                networkAddress(selected.source_ip, selected.source_port),
              ],
              [
                "Дестинация",
                networkAddress(
                  selected.destination_ip,
                  selected.destination_port,
                ),
              ],
              ["Протокол", selected.protocol || "—"],
              ["Интерфейс", selected.interface || "—"],
              ["Flow ID", selected.flow_id || "—"],
              ["Посока", selected.direction || "—"],
            ]}
          />
          <div className="form-footer">
            <button
              className="secondary danger"
              disabled={op.busy}
              onClick={() =>
                op.confirm(
                  "Създаване на блокиращо правило?",
                  `Ще бъде създадено входящо Firewall правило за ${selected.source_ip}. След това трябва да го приложите от модула Firewall. Частни и служебни адреси се отхвърлят от сървъра.`,
                  () =>
                    op.run(
                      () =>
                        apiPost(`/ips/events/${selected.id}/block-source/`, {}),
                      "Firewall правилото е създадено. Прегледайте и приложете политиката в модула Firewall.",
                    ),
                )
              }
            >
              <Shield size={16} />
              Създай блокиращо правило
            </button>
          </div>
          <details className="technical-details">
            <summary>Пълно събитие · EVE JSON</summary>
            <pre className="code-block">
              {JSON.stringify(selected.raw_event || {}, null, 2)}
            </pre>
          </details>
        </Drawer>
      )}
    </ModuleFrame>
  );
}
