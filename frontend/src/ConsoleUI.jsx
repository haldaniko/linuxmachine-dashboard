import {
  Children,
  cloneElement,
  isValidElement,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  AlertCircle,
  ArrowDown,
  ArrowUp,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Download,
  Inbox,
  Loader2,
  Search,
  Settings2,
  X,
} from "lucide-react";

const base = (import.meta.env.BASE_URL || "/").replace(/\/$/, "");
export const API_BASE = import.meta.env.VITE_API_BASE_URL || `${base}/api`;
export const TOKEN_KEY = "soc_control_token";

function errorText(payload) {
  if (typeof payload === "string") return payload;
  if (Array.isArray(payload)) return payload.map(errorText).join(" ");
  if (!payload || typeof payload !== "object") return "";
  return Object.entries(payload)
    .map(
      ([key, value]) =>
        `${["detail", "error", "message", "non_field_errors"].includes(key) ? "" : `${key}: `}${errorText(value)}`,
    )
    .join(" · ");
}

export async function apiRequest(path, options = {}) {
  const token = localStorage.getItem(TOKEN_KEY);
  const controller = new AbortController();
  const timeout = setTimeout(
    () => controller.abort(),
    options.timeoutMs || 30000,
  );
  try {
    const response = await fetch(`${API_BASE}${path}`, {
      ...options,
      signal: options.signal || controller.signal,
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Token ${token}` } : {}),
        ...options.headers,
      },
    });
    if (!response.ok) {
      const payload = await response.json().catch(() => null);
      if (response.status === 401)
        window.dispatchEvent(new CustomEvent("soc:session-expired"));
      const error = new Error(
        errorText(payload) ||
          `Неуспешна заявка (${response.status}). Опитайте отново.`,
      );
      error.status = response.status;
      throw error;
    }
    return response.status === 204 ? null : response.json();
  } catch (error) {
    if (error.name === "AbortError")
      throw new Error("Сървърът не отговори навреме. Опитайте отново.");
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}
export const apiGet = (path) => apiRequest(path);
export const apiPost = (path, body) =>
  apiRequest(path, { method: "POST", body: JSON.stringify(body) });
export const apiPatch = (path, body) =>
  apiRequest(path, { method: "PATCH", body: JSON.stringify(body) });
export const apiDelete = (path) => apiRequest(path, { method: "DELETE" });
export const formatNumber = (value) =>
  new Intl.NumberFormat("bg-BG").format(value ?? 0);
export function formatDate(value) {
  if (!value || Number.isNaN(new Date(value).getTime())) return "—";
  return new Intl.DateTimeFormat("bg-BG", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value));
}

const labels = {
  enabled: "Активно",
  disabled: "Изключено",
  online: "Онлайн",
  offline: "Офлайн",
  never_connected: "Не е свързван",
  healthy: "Нормално",
  warning: "Внимание",
  error: "Грешка",
  unknown: "Неизвестно",
  allow: "Разрешен",
  deny: "Забранен",
  block: "Блокиран",
  drop: "Блокиран",
  reject: "Отхвърлен",
  review: "За преглед",
  alert: "Сигнал",
  log: "Запис",
  critical: "Критична",
  high: "Висока",
  medium: "Средна",
  low: "Ниска",
  informational: "Информация",
  protected: "Защитен",
  attention: "Внимание",
  at_risk: "В риск",
  new: "Нова",
  investigating: "Разследва се",
  resolved: "Решена",
  ignored: "Игнорирана",
  blocked: "Блокирана",
  open: "Отворена",
  monitor: "Наблюдение",
  enforce: "Прилагане",
  running: "Работи",
  stopped: "Спрян",
  active: "Активно",
  inactive: "Неактивно",
};
export function StatusBadge({ value, label }) {
  const tone = [
    "enabled",
    "online",
    "healthy",
    "allow",
    "protected",
    "resolved",
    "running",
    "active",
  ].includes(value)
    ? "success"
    : [
          "critical",
          "high",
          "block",
          "blocked",
          "deny",
          "drop",
          "error",
          "at_risk",
          "reject",
        ].includes(value)
      ? "danger"
      : [
            "warning",
            "medium",
            "review",
            "alert",
            "attention",
            "new",
            "investigating",
          ].includes(value)
        ? "warning"
        : "neutral";
  return (
    <span className={`status-badge badge-${tone}`}>
      <i aria-hidden="true" />
      {label || labels[value] || value || "Неизвестно"}
    </span>
  );
}
export function Notice({ message, onClose }) {
  if (!message) return null;
  return (
    <div
      className={`notice ${message.tone || "info"}`}
      role={message.tone === "danger" ? "alert" : "status"}
    >
      {message.tone === "ok" ? (
        <CheckCircle2 size={17} />
      ) : (
        <AlertCircle size={17} />
      )}
      <span>{message.text}</span>
      {onClose && (
        <button
          type="button"
          className="icon-button"
          onClick={onClose}
          aria-label="Затвори съобщението"
        >
          <X size={15} />
        </button>
      )}
    </div>
  );
}
export function Field({ label, hint, children }) {
  const generatedId = useId();
  const control = Children.toArray(children).find(
    (child) =>
      isValidElement(child) &&
      ["input", "select", "textarea"].includes(child.type),
  );
  const id = control?.props.id || generatedId;
  return (
    <div className="field">
      {control ? <label htmlFor={id}>{label}</label> : <span>{label}</span>}
      {Children.map(children, (child) =>
        isValidElement(child) &&
        ["input", "select", "textarea"].includes(child.type)
          ? cloneElement(child, {
              id,
              "aria-describedby": hint
                ? `${id}-hint`
                : child.props["aria-describedby"],
            })
          : child,
      )}
      {hint && <small id={`${id}-hint`}>{hint}</small>}
    </div>
  );
}
export function Toggle({ checked, onChange, disabled, label }) {
  return (
    <button
      type="button"
      className={`toggle ${checked ? "on" : ""}`}
      role="switch"
      aria-checked={Boolean(checked)}
      aria-label={label || "Активност"}
      title={label || (checked ? "Изключи" : "Включи")}
      disabled={disabled}
      onClick={() => onChange(!checked)}
    >
      <span />
    </button>
  );
}
export function Panel({
  title,
  description,
  actions,
  children,
  className = "",
}) {
  return (
    <section className={`console-panel ${className}`}>
      {(title || actions) && (
        <div className="console-panel-heading">
          <div>
            <h2>{title}</h2>
            {description && <p>{description}</p>}
          </div>
          {actions && <div className="panel-toolbar">{actions}</div>}
        </div>
      )}
      {children}
    </section>
  );
}
export function ModuleFrame({
  eyebrow,
  title,
  description,
  status,
  actions,
  metrics = [],
  children,
}) {
  return (
    <div className="workspace">
      <section className="workspace-heading">
        <div>
          <div className="eyebrow">{eyebrow || "ЦЕНТЪР ЗА СИГУРНОСТ"}</div>
          <div className="workspace-title">
            <h1>{title}</h1>
            {status}
          </div>
          <p>{description}</p>
        </div>
        <div className="workspace-actions">{actions}</div>
      </section>
      {metrics.length > 0 && (
        <div className="workspace-metrics">
          {metrics.map((metric, index) => (
            <div
              className={`workspace-metric ${metric.tone || ""}`}
              key={index}
            >
              <span>{metric.label}</span>
              <strong
                className={
                  String(metric.value ?? "").length > 12 ? "metric-detail" : ""
                }
              >
                {metric.value ?? "—"}
              </strong>
              {metric.hint && <small>{metric.hint}</small>}
            </div>
          ))}
        </div>
      )}
      {children}
    </div>
  );
}
export function Tabs({ items, value, onChange }) {
  return (
    <div
      className="workspace-tabs"
      role="tablist"
      aria-label="Раздели на модула"
    >
      {items.map((item) => (
        <button
          key={item.key}
          role="tab"
          aria-selected={value === item.key}
          className={value === item.key ? "active" : ""}
          onClick={() => onChange(item.key)}
        >
          {item.label}
          {item.count != null && <span>{formatNumber(item.count)}</span>}
        </button>
      ))}
    </div>
  );
}

function csvValue(value) {
  const text = String(value ?? "");
  const safe = /^[=+\-@\t\r]/.test(text) ? `'${text}` : text;
  return `"${safe.replaceAll('"', '""')}"`;
}
export function DataTable({
  rows = [],
  columns,
  searchPlaceholder = "Търсене в записите…",
  emptyTitle = "Все още няма записи",
  emptyDescription = "Новите записи ще се появят тук.",
  onRowClick,
  toolbar,
  exportName,
  pageSize = 10,
  filters = [],
}) {
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState({});
  const [sort, setSort] = useState({ key: null, direction: 1 });
  const [page, setPage] = useState(1);
  const [size, setSize] = useState(pageSize);
  const filtered = useMemo(() => {
    const query = search.trim().toLocaleLowerCase("bg");
    const result = rows.filter(
      (row) =>
        (!query ||
          columns.some((column) =>
            String(
              column.searchValue
                ? column.searchValue(row)
                : (row[column.key] ?? ""),
            )
              .toLocaleLowerCase("bg")
              .includes(query),
          )) &&
        filters.every(
          (filter) =>
            !selected[filter.key] ||
            String(row[filter.key]) === selected[filter.key],
        ),
    );
    if (sort.key) {
      const column = columns.find((item) => item.key === sort.key);
      if (column)
        result.sort((a, b) => {
          const av = column.sortValue ? column.sortValue(a) : a[sort.key];
          const bv = column.sortValue ? column.sortValue(b) : b[sort.key];
          return (
            (typeof av === "number" && typeof bv === "number"
              ? av - bv
              : String(av ?? "").localeCompare(String(bv ?? ""), "bg", {
                  numeric: true,
                })) * sort.direction
          );
        });
    }
    return result;
  }, [rows, columns, search, selected, sort, filters]);
  const pages = Math.max(1, Math.ceil(filtered.length / size));
  const currentPage = Math.min(page, pages);
  const visible = filtered.slice((currentPage - 1) * size, currentPage * size);
  const exportRows = () => {
    const exported = columns.filter(
      (column) =>
        !["actions", "operations"].includes(column.key) &&
        column.export !== false,
    );
    const csv = [
      exported.map((column) => csvValue(column.label)).join(","),
      ...filtered.map((row) =>
        exported
          .map((column) =>
            csvValue(
              column.exportValue ? column.exportValue(row) : row[column.key],
            ),
          )
          .join(","),
      ),
    ].join("\r\n");
    const url = URL.createObjectURL(
      new Blob(["\ufeff", csv], { type: "text/csv;charset=utf-8;" }),
    );
    const link = document.createElement("a");
    link.href = url;
    link.download = `${exportName}.csv`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  return (
    <div className="table-container">
      <div className="table-toolbar">
        <label className="table-search">
          <Search size={17} />
          <input
            aria-label={searchPlaceholder}
            placeholder={searchPlaceholder}
            value={search}
            onChange={(event) => {
              setSearch(event.target.value);
              setPage(1);
            }}
          />
          {search && (
            <button
              type="button"
              className="icon-button"
              aria-label="Изчисти търсенето"
              onClick={() => {
                setSearch("");
                setPage(1);
              }}
            >
              <X size={14} />
            </button>
          )}
        </label>
        {filters.map((filter) => (
          <select
            aria-label={filter.label}
            key={filter.key}
            value={selected[filter.key] || ""}
            onChange={(event) => {
              setSelected({ ...selected, [filter.key]: event.target.value });
              setPage(1);
            }}
          >
            <option value="">{filter.label}</option>
            {filter.options.map(([value, label]) => (
              <option value={value} key={value}>
                {label}
              </option>
            ))}
          </select>
        ))}
        <div className="table-toolbar-end">
          {toolbar}
          {exportName && (
            <button
              className="secondary"
              onClick={exportRows}
              disabled={!filtered.length}
            >
              <Download size={15} />
              Експорт
            </button>
          )}
        </div>
      </div>
      <div className="table-scroll">
        <table className="console-table">
          <thead>
            <tr>
              {columns.map((column) => (
                <th
                  key={column.key}
                  aria-sort={
                    sort.key === column.key
                      ? sort.direction === 1
                        ? "ascending"
                        : "descending"
                      : undefined
                  }
                >
                  {column.sortable === false ||
                  ["actions", "operations"].includes(column.key) ? (
                    column.label
                  ) : (
                    <button
                      onClick={() =>
                        setSort({
                          key: column.key,
                          direction:
                            sort.key === column.key ? -sort.direction : 1,
                        })
                      }
                    >
                      {column.label}
                      {sort.key === column.key &&
                        (sort.direction === 1 ? (
                          <ArrowUp size={13} />
                        ) : (
                          <ArrowDown size={13} />
                        ))}
                    </button>
                  )}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {visible.map((row, index) => (
              <tr key={row.id ?? index}>
                {columns.map((column, columnIndex) => (
                  <td key={column.key}>
                    {columnIndex === 0 && onRowClick ? (
                      <button
                        className="table-link"
                        onClick={() => onRowClick(row)}
                      >
                        {column.render
                          ? column.render(row)
                          : (row[column.key] ?? "—")}
                      </button>
                    ) : column.render ? (
                      column.render(row)
                    ) : (
                      (row[column.key] ?? "—")
                    )}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!visible.length && (
        <div className="table-empty">
          <Inbox size={28} />
          <strong>
            {rows.length ? "Няма съвпадащи резултати" : emptyTitle}
          </strong>
          <p>
            {rows.length
              ? "Променете търсенето или изчистете филтрите."
              : emptyDescription}
          </p>
          {rows.length > 0 && (
            <button
              className="secondary"
              onClick={() => {
                setSearch("");
                setSelected({});
              }}
            >
              Изчисти филтрите
            </button>
          )}
        </div>
      )}
      <div className="table-footer">
        <span>
          {filtered.length
            ? `${(currentPage - 1) * size + 1}–${Math.min(currentPage * size, filtered.length)}`
            : "0"}{" "}
          от {formatNumber(filtered.length)}
          {filtered.length !== rows.length &&
            ` · общо ${formatNumber(rows.length)}`}
        </span>
        <div>
          <label>
            Редове{" "}
            <select
              aria-label="Редове на страница"
              value={size}
              onChange={(event) => {
                setSize(Number(event.target.value));
                setPage(1);
              }}
            >
              {[...new Set([pageSize, 10, 25, 50])]
                .sort((a, b) => a - b)
                .map((value) => (
                  <option key={value}>{value}</option>
                ))}
            </select>
          </label>
          <button
            className="icon-button"
            disabled={currentPage === 1}
            onClick={() => setPage(currentPage - 1)}
            aria-label="Предишна страница"
          >
            <ChevronLeft size={16} />
          </button>
          <span>
            {currentPage} / {pages}
          </span>
          <button
            className="icon-button"
            disabled={currentPage === pages}
            onClick={() => setPage(currentPage + 1)}
            aria-label="Следваща страница"
          >
            <ChevronRight size={16} />
          </button>
        </div>
      </div>
    </div>
  );
}

const dialogStack = [];
export function Drawer({
  title,
  description,
  onClose,
  children,
  compact = false,
}) {
  const ref = useRef(null);
  const closeRef = useRef(onClose);
  closeRef.current = onClose;
  const id = useId();
  useEffect(() => {
    const previous = document.activeElement;
    const node = ref.current;
    dialogStack.push(node);
    const overflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    ref.current?.focus();
    const keydown = (event) => {
      if (dialogStack.at(-1) !== node) return;
      if (event.key === "Escape") {
        event.preventDefault();
        closeRef.current?.();
      }
      if (event.key !== "Tab") return;
      const items = [
        ...ref.current.querySelectorAll(
          'button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), a[href], [tabindex="0"]',
        ),
      ].filter((item) => item.offsetParent !== null);
      if (!items.length) {
        event.preventDefault();
        return;
      }
      if (
        event.shiftKey &&
        (document.activeElement === items[0] ||
          document.activeElement === ref.current)
      ) {
        event.preventDefault();
        items.at(-1).focus();
      } else if (
        !event.shiftKey &&
        (document.activeElement === items.at(-1) ||
          document.activeElement === ref.current)
      ) {
        event.preventDefault();
        items[0].focus();
      }
    };
    document.addEventListener("keydown", keydown);
    return () => {
      dialogStack.splice(dialogStack.indexOf(node), 1);
      document.body.style.overflow = dialogStack.length
        ? "hidden"
        : overflow === "hidden"
          ? ""
          : overflow;
      document.removeEventListener("keydown", keydown);
      previous?.focus();
    };
  }, []);
  return (
    <div
      className={`console-overlay ${compact ? "centered" : ""}`}
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose?.();
      }}
    >
      <section
        className={`console-drawer ${compact ? "compact" : ""}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby={id}
        tabIndex={-1}
        ref={ref}
      >
        <header>
          <div>
            <span className="eyebrow">SOC CONTROL</span>
            <h2 id={id}>{title}</h2>
            {description && <p>{description}</p>}
          </div>
          <button
            className="icon-button"
            aria-label="Затвори"
            onClick={onClose}
          >
            <X size={20} />
          </button>
        </header>
        <div className="drawer-content">{children}</div>
      </section>
    </div>
  );
}
export function ConfirmDialog({
  title,
  description,
  onConfirm,
  onClose,
  busy,
}) {
  return (
    <Drawer
      title={title}
      description={description}
      onClose={() => !busy && onClose()}
      compact
    >
      <div className="form-footer">
        <button className="secondary" onClick={onClose} disabled={busy}>
          Отказ
        </button>
        <button
          className="primary danger-button"
          disabled={busy}
          onClick={onConfirm}
        >
          {busy && <Loader2 size={16} className="spin" />}Потвърди
        </button>
      </div>
    </Drawer>
  );
}

const settingSchemas = {
  firewall: [
    {
      key: "default_action",
      label: "Решение при липса на правило",
      options: [
        ["allow", "Разреши"],
        ["block", "Блокирай"],
        ["log", "Само запис"],
      ],
      fallback: "allow",
    },
    {
      key: "log_allowed",
      label: "Запис на разрешените връзки",
      type: "boolean",
      fallback: true,
    },
  ],
  web_filter: [
    {
      key: "default_action",
      label: "Решение при липса на правило",
      options: [
        ["allow", "Разреши"],
        ["block", "Блокирай"],
        ["review", "За преглед"],
      ],
      fallback: "allow",
    },
    {
      key: "log_allowed",
      label: "Запис на разрешените посещения",
      type: "boolean",
      fallback: false,
    },
  ],
  access: [
    {
      key: "default_effect",
      label: "Достъп при липса на правило",
      options: [
        ["deny", "Забрани"],
        ["allow", "Разреши"],
        ["review", "За преглед"],
      ],
      fallback: "deny",
    },
  ],
};
export function SettingsForm({ setting, moduleKey, onSave }) {
  const schema = settingSchemas[moduleKey] || [];
  const initial = () => ({
    enabled: setting?.enabled ?? true,
    mode: setting?.mode || "monitor",
    notes: setting?.notes || "",
    settings: {
      ...Object.fromEntries(schema.map((field) => [field.key, field.fallback])),
      ...setting?.settings,
    },
  });
  const [draft, setDraft] = useState(initial);
  const [baseline, setBaseline] = useState(() => JSON.stringify(initial()));
  const [message, setMessage] = useState(null);
  const [busy, setBusy] = useState(false);
  const dirty = JSON.stringify(draft) !== baseline;
  useEffect(() => {
    const key = `settings-${moduleKey}`;
    window.dispatchEvent(
      new CustomEvent("console-dirty", {
        detail: { key, dirty: dirty || busy },
      }),
    );
    return () =>
      window.dispatchEvent(
        new CustomEvent("console-dirty", { detail: { key, dirty: false } }),
      );
  }, [moduleKey, dirty, busy]);
  useEffect(() => {
    if (!dirty) {
      const next = initial();
      setDraft(next);
      setBaseline(JSON.stringify(next));
    }
  }, [setting?.id, setting?.updated_at]);
  useEffect(() => {
    if (!dirty) return;
    const warn = (event) => {
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [dirty]);
  const save = async (event) => {
    event.preventDefault();
    setBusy(true);
    setMessage(null);
    try {
      await onSave(setting.id, draft);
      setBaseline(JSON.stringify(draft));
      setMessage({ tone: "ok", text: "Настройките са запазени успешно." });
    } catch (error) {
      setMessage({ tone: "danger", text: error.message });
    } finally {
      setBusy(false);
    }
  };
  return (
    <Panel
      title="Политика и настройки"
      description="Поведението на модула при обработка на нови заявки."
    >
      <form className="settings-form" onSubmit={save}>
        <Notice message={message} />
        {!setting && (
          <Notice
            message={{
              tone: "warn",
              text: "Настройките не са достъпни. Обновете данните, преди да направите промени.",
            }}
          />
        )}
        <div className="settings-section">
          <div className="settings-section-title">
            <Settings2 size={19} />
            <div>
              <h3>Режим на защита</h3>
              <p>Определя как се обработват съвпаденията.</p>
            </div>
          </div>
          <div className="settings-fields">
            <div className="setting-toggle">
              <div>
                <strong>Модулът е активен</strong>
                <p>
                  Изключването прекратява прилагането на политиката в оценката.
                </p>
              </div>
              <Toggle
                label="Активирай модула"
                checked={draft.enabled}
                onChange={(enabled) => setDraft({ ...draft, enabled })}
              />
            </div>
            <Field label="Режим">
              <select
                value={draft.mode}
                onChange={(event) =>
                  setDraft({ ...draft, mode: event.target.value })
                }
              >
                <option value="monitor">Наблюдение</option>
                <option value="enforce">Прилагане на политиката</option>
                <option value="disabled">Изключен</option>
              </select>
            </Field>
            {schema.map((field) =>
              field.type === "boolean" ? (
                <div className="setting-toggle" key={field.key}>
                  <strong>{field.label}</strong>
                  <Toggle
                    label={field.label}
                    checked={Boolean(draft.settings[field.key])}
                    onChange={(value) =>
                      setDraft({
                        ...draft,
                        settings: { ...draft.settings, [field.key]: value },
                      })
                    }
                  />
                </div>
              ) : (
                <Field label={field.label} key={field.key}>
                  <select
                    value={draft.settings[field.key]}
                    onChange={(event) =>
                      setDraft({
                        ...draft,
                        settings: {
                          ...draft.settings,
                          [field.key]: event.target.value,
                        },
                      })
                    }
                  >
                    {field.options.map(([value, label]) => (
                      <option value={value} key={value}>
                        {label}
                      </option>
                    ))}
                  </select>
                </Field>
              ),
            )}
          </div>
        </div>
        <div className="settings-section">
          <div className="settings-section-title">
            <div>
              <h3>Административна бележка</h3>
              <p>Контекст за останалите оператори.</p>
            </div>
          </div>
          <Field label="Бележка">
            <textarea
              rows={3}
              value={draft.notes}
              onChange={(event) =>
                setDraft({ ...draft, notes: event.target.value })
              }
              placeholder="Собственик, обхват или причина за промяната"
            />
          </Field>
        </div>
        {moduleKey === "firewall" && (
          <Notice
            message={{
              tone: "info",
              text: "Запазените настройки се използват веднага при API оценка. За nftables приложете конфигурацията от раздел „Правила“.",
            }}
          />
        )}
        <div className="settings-footer">
          <span>
            {dirty
              ? "Има незапазени промени"
              : `Последна промяна: ${formatDate(setting?.updated_at)}`}
          </span>
          <div>
            <button
              className="secondary"
              type="button"
              disabled={!dirty || busy}
              onClick={() => {
                setDraft(JSON.parse(baseline));
                setMessage(null);
              }}
            >
              Отмени промените
            </button>
            <button className="primary" disabled={!dirty || busy || !setting}>
              {busy && <Loader2 size={16} className="spin" />}Запази настройките
            </button>
          </div>
        </div>
      </form>
    </Panel>
  );
}
