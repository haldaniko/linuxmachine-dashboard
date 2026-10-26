import { useEffect, useMemo, useState } from "react";
import {
  ArrowRight,
  Copy,
  Globe,
  LockKeyhole,
  Pencil,
  Play,
  Plus,
  RefreshCw,
  ShieldCheck,
  Trash2,
  Users,
} from "lucide-react";
import {
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

const NETWORKS = [
  ["any", "Всички връзки"],
  ["wired", "Кабелна мрежа"],
  ["wireless", "Wi-Fi"],
  ["vpn", "VPN"],
  ["admin", "Административен достъп"],
];
const MATCH_TYPES = [
  ["domain", "Домейн и поддомейни"],
  ["contains", "Част от URL адреса"],
  ["regex", "Регулярен израз"],
];
const WEB_ACTIONS = [
  ["block", "Блокирай"],
  ["allow", "Разреши"],
  ["review", "За преглед"],
];
const ACCESS_ACTIONS = [
  ["allow", "Разреши"],
  ["deny", "Забрани"],
  ["review", "За преглед"],
];
const ENABLED_FILTER = {
  key: "enabled",
  label: "Състояние",
  options: [
    ["true", "Активни"],
    ["false", "Изключени"],
  ],
};
const labelFor = (options, value) =>
  options.find(([key]) => key === value)?.[1] || value || "—";
const priorityOrder = (left, right) =>
  left.priority - right.priority || left.id - right.id;

const POLICY_CONFIG = {
  web_filter: {
    title: "Web Filter",
    eyebrow: "МРЕЖОВА СИГУРНОСТ",
    description:
      "Контрол на интернет достъпа чрез подредени правила за домейни и URL адреси.",
    rulesKey: "webRules",
    endpoint: "/web-filter",
    verdictKey: "action",
    actions: WEB_ACTIONS,
    rulesTitle: "Правила за сайтове",
    testTitle: "Провери сайт",
    entity: "сайт",
    Icon: Globe,
  },
  access: {
    title: "IAM / MFA",
    eyebrow: "ИДЕНТИЧНОСТ И ДОСТЪП",
    description:
      "Правила за мрежов достъп, изисквания за MFA и локални администраторски акаунти.",
    rulesKey: "accessRules",
    endpoint: "/access",
    verdictKey: "effect",
    actions: ACCESS_ACTIONS,
    rulesTitle: "Правила за достъп",
    testTitle: "Провери достъп",
    entity: "достъп",
    Icon: LockKeyhole,
  },
};

function SelectOptions({ options }) {
  return options.map(([value, label]) => (
    <option key={value} value={value}>
      {label}
    </option>
  ));
}

function useDraftGuard(key, dirty) {
  useEffect(() => {
    window.dispatchEvent(
      new CustomEvent("console-dirty", { detail: { key, dirty } }),
    );
    const warn = (event) => {
      event.preventDefault();
      event.returnValue = "";
    };
    if (dirty) window.addEventListener("beforeunload", warn);
    return () => {
      window.dispatchEvent(
        new CustomEvent("console-dirty", { detail: { key, dirty: false } }),
      );
      window.removeEventListener("beforeunload", warn);
    };
  }, [key, dirty]);
}

function DiscardChanges({ onKeep, onDiscard }) {
  return (
    <div className="drawer-form">
      <div className="console-callout">
        Има незапазени промени. Ако затворите формата, въведеното ще бъде
        загубено.
      </div>
      <div className="form-footer">
        <button type="button" className="secondary" onClick={onKeep}>
          Продължи редакцията
        </button>
        <button
          type="button"
          className="primary danger-button"
          onClick={onDiscard}
        >
          Отхвърли промените
        </button>
      </div>
    </div>
  );
}

function moduleStatus(setting) {
  if (!setting)
    return <StatusBadge value="unknown" label="Няма конфигурация" />;
  if (!setting.enabled || setting.mode === "disabled")
    return <StatusBadge value="disabled" label="Изключен" />;
  return setting.mode === "enforce" ? (
    <StatusBadge value="healthy" label="Прилагане на политики" />
  ) : (
    <StatusBadge value="monitor" label="Наблюдение" />
  );
}

function newRule(moduleKey, rules) {
  const priority = Math.min(
    Math.max(0, ...rules.map((rule) => Number(rule.priority) || 0)) + 10,
    2147483647,
  );
  return moduleKey === "web_filter"
    ? {
        name: "",
        enabled: true,
        priority,
        match_type: "domain",
        pattern: "",
        category: "",
        action: "block",
      }
    : {
        name: "",
        enabled: true,
        priority,
        network_type: "vpn",
        group: "any",
        mfa_required: true,
        effect: "allow",
      };
}

function editableRule(moduleKey, rule) {
  const keys =
    moduleKey === "web_filter"
      ? [
          "name",
          "enabled",
          "priority",
          "match_type",
          "pattern",
          "category",
          "action",
        ]
      : [
          "name",
          "enabled",
          "priority",
          "network_type",
          "group",
          "mfa_required",
          "effect",
        ];
  return Object.fromEntries(keys.map((key) => [key, rule[key]]));
}

export function WebFilterWorkspace(props) {
  return <PolicyWorkspace {...props} moduleKey="web_filter" />;
}

export function AccessWorkspace(props) {
  return <PolicyWorkspace {...props} moduleKey="access" />;
}

function PolicyWorkspace({ data, actions, moduleKey }) {
  const config = POLICY_CONFIG[moduleKey];
  const isWeb = moduleKey === "web_filter";
  const rules = useMemo(
    () => [...(data[config.rulesKey] || [])].sort(priorityOrder),
    [data, config.rulesKey],
  );
  const setting = (data.settings || []).find((item) => item.key === moduleKey);
  const events = useMemo(
    () =>
      (data.events || [])
        .filter((event) => event.component_key === moduleKey)
        .map((event) => ({
          ...event,
          action: event.extra_data?.action || "",
          username: event.extra_data?.username || event.destination,
        })),
    [data.events, moduleKey],
  );
  const [tab, setTab] = useState("rules");
  const [editor, setEditor] = useState(null);
  const [deleting, setDeleting] = useState(null);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [message, setMessage] = useState(null);
  const [busy, setBusy] = useState("");
  const [categoryFilter, setCategoryFilter] = useState(null);

  const activeRules = rules.filter((rule) => rule.enabled);
  const categoryNames = [
    ...new Set(rules.map((rule) => rule.category || "").filter(Boolean)),
  ].sort((a, b) => a.localeCompare(b, "bg"));
  const filteredRules =
    categoryFilter === null
      ? rules
      : rules.filter((rule) => (rule.category || "") === categoryFilter);
  const lastUpdate = rules
    .map((rule) => rule.updated_at)
    .filter(Boolean)
    .sort()
    .at(-1);
  const openNew = () =>
    setEditor({ id: null, draft: newRule(moduleKey, rules) });
  const openEdit = (rule) =>
    setEditor({ id: rule.id, draft: editableRule(moduleKey, rule) });
  const duplicate = (rule) =>
    setEditor({
      id: null,
      draft: {
        ...editableRule(moduleKey, rule),
        name: `Копие · ${rule.name}`.slice(0, 140),
        enabled: false,
        priority: newRule(moduleKey, rules).priority,
      },
    });

  async function mutate(key, operation, successText) {
    if (busy) return false;
    setBusy(key);
    setMessage(null);
    try {
      await operation();
      await actions.reload();
      setMessage({ tone: "ok", text: successText });
      return true;
    } catch (error) {
      setMessage({ tone: "danger", text: error.message });
      return false;
    } finally {
      setBusy("");
    }
  }

  const columns = [
    {
      key: "priority",
      label: "Ред",
      render: (rule) => (
        <button
          type="button"
          className="rule-priority"
          title="Редактирай приоритета"
          onClick={() => openEdit(rule)}
        >
          {rule.priority}
        </button>
      ),
    },
    {
      key: "name",
      label: "Правило",
      searchValue: (rule) =>
        `${rule.name} ${isWeb ? labelFor(MATCH_TYPES, rule.match_type) : labelFor(NETWORKS, rule.network_type)}`,
      render: (rule) => (
        <>
          <button
            type="button"
            className="cell-title text-button"
            onClick={() => openEdit(rule)}
          >
            {rule.name}
          </button>
          <span className="cell-subtitle">
            {isWeb
              ? labelFor(MATCH_TYPES, rule.match_type)
              : labelFor(NETWORKS, rule.network_type)}
          </span>
        </>
      ),
    },
    ...(isWeb
      ? [
          {
            key: "pattern",
            label: "Съвпадение",
            render: (rule) => <span className="mono">{rule.pattern}</span>,
          },
          {
            key: "category",
            label: "Категория",
            render: (rule) =>
              rule.category || <span className="muted">Без категория</span>,
          },
        ]
      : [
          {
            key: "group",
            label: "Група",
            render: (rule) => (
              <span className="mono">
                {["any", "*"].includes(rule.group)
                  ? "Всички групи"
                  : rule.group}
              </span>
            ),
          },
          {
            key: "mfa_required",
            label: "MFA",
            render: (rule) => (
              <StatusBadge
                value={rule.mfa_required ? "healthy" : "disabled"}
                label={rule.mfa_required ? "Задължителна" : "Не се изисква"}
              />
            ),
          },
        ]),
    {
      key: config.verdictKey,
      label: "Действие",
      render: (rule) => (
        <StatusBadge
          value={rule[config.verdictKey]}
          label={labelFor(config.actions, rule[config.verdictKey])}
        />
      ),
    },
    {
      key: "hit_count",
      label: "Съвпадения",
      render: (rule) => (
        <span
          title={
            rule.last_matched
              ? `Последно: ${formatDate(rule.last_matched)}`
              : "Няма отчетени съвпадения"
          }
        >
          {formatNumber(rule.hit_count || 0)}
        </span>
      ),
    },
    {
      key: "enabled",
      label: "Активно",
      render: (rule) => (
        <Toggle
          checked={rule.enabled}
          disabled={Boolean(busy)}
          label={`${rule.enabled ? "Изключи" : "Включи"} ${rule.name}`}
          onChange={(enabled) =>
            mutate(
              `toggle-${rule.id}`,
              () =>
                apiPatch(`${config.endpoint}/rules/${rule.id}/`, { enabled }),
              `Правилото „${rule.name}“ е ${enabled ? "включено" : "изключено"}.`,
            )
          }
        />
      ),
    },
    {
      key: "actions",
      label: "Действия",
      render: (rule) => (
        <div className="table-actions">
          <button
            type="button"
            className="icon-button"
            title="Редактирай правило"
            aria-label={`Редактирай ${rule.name}`}
            onClick={() => openEdit(rule)}
          >
            <Pencil size={15} />
          </button>
          <button
            type="button"
            className="icon-button"
            title="Създай копие"
            aria-label={`Копирай ${rule.name}`}
            onClick={() => duplicate(rule)}
          >
            <Copy size={15} />
          </button>
          <button
            type="button"
            className="icon-button danger"
            disabled={Boolean(busy)}
            title="Изтрий правило"
            aria-label={`Изтрий ${rule.name}`}
            onClick={() => setDeleting(rule)}
          >
            <Trash2 size={15} />
          </button>
        </div>
      ),
    },
  ];

  const tabs = [
    { key: "rules", label: config.rulesTitle, count: rules.length },
    ...(isWeb
      ? [{ key: "categories", label: "Категории", count: categoryNames.length }]
      : []),
    { key: "test", label: config.testTitle },
    { key: "events", label: "Събития", count: events.length },
    ...(!isWeb && actions.user?.is_staff
      ? [
          {
            key: "users",
            label: "Потребители",
            count: (data.users || []).length,
          },
        ]
      : []),
    { key: "settings", label: "Настройки" },
  ];

  return (
    <ModuleFrame
      eyebrow={config.eyebrow}
      title={config.title}
      description={config.description}
      status={moduleStatus(setting)}
      actions={
        <>
          <button
            type="button"
            className="secondary"
            disabled={Boolean(busy)}
            onClick={() =>
              mutate("refresh", async () => {}, "Данните са обновени.")
            }
          >
            <RefreshCw
              size={16}
              className={busy === "refresh" ? "spinning" : ""}
            />
            Обнови
          </button>
          <button type="button" className="primary" onClick={openNew}>
            <Plus size={16} />
            Ново правило
          </button>
        </>
      }
      metrics={[
        {
          label: "Активни правила",
          value: formatNumber(activeRules.length),
          hint: `${formatNumber(rules.length)} общо в политиката`,
        },
        {
          label: isWeb ? "Блокиращи правила" : "Изискват MFA",
          value: formatNumber(
            activeRules.filter((rule) =>
              isWeb ? rule.action === "block" : rule.mfa_required,
            ).length,
          ),
          hint: isWeb
            ? "Активни ограничения"
            : "Активни правила с втори фактор",
        },
        {
          label: "Отчетени съвпадения",
          value: formatNumber(
            rules.reduce((sum, rule) => sum + (rule.hit_count || 0), 0),
          ),
          hint: "Натрупани от реални проверки",
        },
        {
          label: isWeb ? "Категории" : "Локални акаунти",
          value: isWeb
            ? formatNumber(categoryNames.length)
            : actions.user?.is_staff
              ? formatNumber((data.users || []).length)
              : "—",
          hint: isWeb
            ? "Групиране на URL правила"
            : actions.user?.is_staff
              ? `${(data.users || []).filter((user) => user.is_active).length} активни потребители`
              : "Достъпно за администратори",
        },
      ]}
    >
      <Notice message={message} onClose={() => setMessage(null)} />
      <Tabs items={tabs} value={tab} onChange={setTab} />

      {tab === "rules" && (
        <Panel
          title={config.rulesTitle}
          description="Прилага се първото активно съвпадение. По-малката стойност на приоритета се проверява първа; при равни стойности се използва редът на създаване."
          actions={
            lastUpdate ? (
              <span className="cell-subtitle">
                Променено {formatDate(lastUpdate)}
              </span>
            ) : null
          }
        >
          <DataTable
            rows={filteredRules}
            columns={columns}
            searchPlaceholder={
              isWeb
                ? "Търси име, домейн или категория…"
                : "Търси име, група или тип връзка…"
            }
            emptyTitle="Няма правила за показване"
            emptyDescription="Добавете правило или променете активните филтри."
            exportName={`${moduleKey}-rules`}
            filters={[
              ENABLED_FILTER,
              {
                key: config.verdictKey,
                label: "Действие",
                options: config.actions,
              },
              ...(isWeb
                ? [
                    {
                      key: "match_type",
                      label: "Тип съвпадение",
                      options: MATCH_TYPES,
                    },
                    {
                      key: "category",
                      label: "Категория",
                      options: categoryNames.map((name) => [name, name]),
                    },
                  ]
                : [
                    {
                      key: "network_type",
                      label: "Тип връзка",
                      options: NETWORKS,
                    },
                    {
                      key: "mfa_required",
                      label: "Изискване за MFA",
                      options: [
                        ["true", "Задължителна"],
                        ["false", "Не се изисква"],
                      ],
                    },
                  ]),
            ]}
            toolbar={
              categoryFilter !== null ? (
                <button
                  type="button"
                  className="secondary"
                  onClick={() => setCategoryFilter(null)}
                >
                  Категория: {categoryFilter || "Без категория"} ×
                </button>
              ) : null
            }
          />
          {rules.length === 0 && (
            <div className="form-footer">
              <button type="button" className="primary" onClick={openNew}>
                <Plus size={16} />
                Създай първо правило
              </button>
            </div>
          )}
        </Panel>
      )}

      {tab === "categories" && isWeb && (
        <CategoryPanel
          rules={rules}
          onSelect={(category) => {
            setCategoryFilter(category);
            setTab("rules");
          }}
          onCreate={openNew}
        />
      )}
      {tab === "test" && (
        <PolicyProbe
          moduleKey={moduleKey}
          rules={rules}
          users={data.users || []}
          onEdit={openEdit}
        />
      )}
      {tab === "events" && (
        <PolicyEvents
          moduleKey={moduleKey}
          events={events}
          onSelect={setSelectedEvent}
        />
      )}
      {tab === "users" && !isWeb && (
        <LocalUsers
          users={data.users || []}
          currentUser={actions.user}
          onReload={actions.reload}
        />
      )}
      <div hidden={tab !== "settings"}>
        <SettingsForm
          setting={setting}
          moduleKey={moduleKey}
          onSave={actions.saveSetting}
        />
      </div>

      {editor && (
        <RuleEditor
          key={`${moduleKey}-${editor.id ?? "new"}`}
          moduleKey={moduleKey}
          editor={editor}
          categories={categoryNames}
          rules={rules}
          onClose={() => setEditor(null)}
          onSaved={async () => {
            setEditor(null);
            await actions.reload();
            setMessage({
              tone: "ok",
              text: editor.id
                ? "Промените по правилото са запазени."
                : "Новото правило е създадено.",
            });
          }}
        />
      )}
      {deleting && (
        <ConfirmDialog
          title="Изтриване на правило"
          description={`Правилото „${deleting.name}“ ще бъде премахнато. Следващите правила и действието по подразбиране ще определят резултата за този ${config.entity}.`}
          busy={busy === "delete"}
          onClose={() => {
            if (!busy) setDeleting(null);
          }}
          onConfirm={async () => {
            await mutate(
              "delete",
              () => apiDelete(`${config.endpoint}/rules/${deleting.id}/`),
              "Правилото е изтрито.",
            );
            setDeleting(null);
          }}
        />
      )}
      {selectedEvent && (
        <EventDetails
          event={selectedEvent}
          isWeb={isWeb}
          onClose={() => setSelectedEvent(null)}
        />
      )}
    </ModuleFrame>
  );
}

function RuleEditor({
  moduleKey,
  editor,
  rules,
  categories,
  onClose,
  onSaved,
}) {
  const config = POLICY_CONFIG[moduleKey];
  const isWeb = moduleKey === "web_filter";
  const [draft, setDraft] = useState(editor.draft);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState(null);
  const [discarding, setDiscarding] = useState(false);
  const dirty = JSON.stringify(draft) !== JSON.stringify(editor.draft);
  useDraftGuard("policy-rule", dirty || busy);
  const close = () => {
    if (!busy) {
      if (dirty) setDiscarding(true);
      else onClose();
    }
  };
  const update = (key, value) =>
    setDraft((current) => ({ ...current, [key]: value }));
  const equalPriority = rules.some(
    (rule) =>
      rule.id !== editor.id && Number(rule.priority) === Number(draft.priority),
  );

  async function save(event) {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setMessage(null);
    const body = {
      ...draft,
      name: draft.name.trim(),
      priority: Number(draft.priority),
    };
    if (isWeb) {
      body.pattern = body.pattern.trim();
      body.category = body.category.trim();
    } else {
      body.group = body.group.trim() || "any";
    }
    try {
      if (!body.name || (isWeb && !body.pattern))
        throw new Error("Попълнете име и валидно условие за правилото.");
      if (editor.id)
        await apiPatch(`${config.endpoint}/rules/${editor.id}/`, body);
      else await apiPost(`${config.endpoint}/rules/`, body);
      await onSaved();
    } catch (error) {
      setMessage({ tone: "danger", text: error.message });
    } finally {
      setBusy(false);
    }
  }

  return (
    <Drawer
      title={
        discarding
          ? "Незапазени промени"
          : editor.id
            ? "Редактиране на правило"
            : "Ново правило"
      }
      description={
        isWeb
          ? "Определете обхвата и действието на URL политиката."
          : "Определете групата, връзката и условията за достъп."
      }
      onClose={close}
    >
      {discarding ? (
        <DiscardChanges
          onKeep={() => setDiscarding(false)}
          onDiscard={onClose}
        />
      ) : (
        <form className="drawer-form" onSubmit={save}>
          <Notice message={message} onClose={() => setMessage(null)} />
          <fieldset className="console-fieldset" disabled={busy}>
            <Field label="Име на правилото">
              <input
                autoFocus
                required
                maxLength={140}
                value={draft.name}
                onChange={(event) => update("name", event.target.value)}
                placeholder={
                  isWeb
                    ? "Напр. ограничаване на рискови домейни"
                    : "Напр. VPN достъп за служители"
                }
              />
            </Field>
            <div className="form-grid">
              <Field
                label="Приоритет"
                hint="По-малкото число се проверява първо."
              >
                <input
                  required
                  type="number"
                  min="0"
                  max="2147483647"
                  step="1"
                  value={draft.priority}
                  onChange={(event) => update("priority", event.target.value)}
                />
              </Field>
              <Field label="Действие">
                <select
                  value={draft[config.verdictKey]}
                  onChange={(event) =>
                    update(config.verdictKey, event.target.value)
                  }
                >
                  <SelectOptions options={config.actions} />
                </select>
              </Field>
            </div>
            {equalPriority && (
              <div className="console-callout">
                Вече има правило с този приоритет. При еднакви стойности първо
                се проверява по-рано създаденото правило.
              </div>
            )}
            {isWeb ? (
              <>
                <Field label="Тип съвпадение">
                  <select
                    value={draft.match_type}
                    onChange={(event) =>
                      update("match_type", event.target.value)
                    }
                  >
                    <SelectOptions options={MATCH_TYPES} />
                  </select>
                </Field>
                <Field
                  label={
                    draft.match_type === "domain"
                      ? "Домейн"
                      : draft.match_type === "regex"
                        ? "Регулярен израз"
                        : "Текст в URL адреса"
                  }
                  hint={
                    draft.match_type === "domain"
                      ? "Въведете домейн без протокол и път, например example.com. Включва и неговите поддомейни."
                      : draft.match_type === "regex"
                        ? "Изразът се проверява върху целия URL без разлика между главни и малки букви."
                        : "Съвпадение с текст във всяка част на URL адреса."
                  }
                >
                  <input
                    required
                    maxLength={260}
                    className="mono"
                    value={draft.pattern}
                    onChange={(event) => update("pattern", event.target.value)}
                    placeholder={
                      draft.match_type === "domain"
                        ? "example.com"
                        : draft.match_type === "regex"
                          ? "example\\.com/.*"
                          : "/downloads/"
                    }
                  />
                </Field>
                <Field
                  label="Категория"
                  hint="Незадължителен етикет за групиране. Условието за съвпадение се задава по-горе."
                >
                  <input
                    list="web-policy-categories"
                    maxLength={120}
                    value={draft.category}
                    onChange={(event) => update("category", event.target.value)}
                    placeholder="Напр. социални мрежи"
                  />
                  <datalist id="web-policy-categories">
                    {categories.map((category) => (
                      <option key={category} value={category} />
                    ))}
                  </datalist>
                </Field>
              </>
            ) : (
              <>
                <Field label="Тип връзка">
                  <select
                    value={draft.network_type}
                    onChange={(event) =>
                      update("network_type", event.target.value)
                    }
                  >
                    <SelectOptions options={NETWORKS} />
                  </select>
                </Field>
                <Field
                  label="Група"
                  hint="Използвайте any за всички групи или точното име на групата."
                >
                  <input
                    required
                    maxLength={140}
                    value={draft.group}
                    onChange={(event) => update("group", event.target.value)}
                    placeholder="employees"
                  />
                </Field>
                <label className="check-row">
                  <input
                    type="checkbox"
                    checked={draft.mfa_required}
                    onChange={(event) =>
                      update("mfa_required", event.target.checked)
                    }
                  />
                  <span>Изисквай потвърдена MFA</span>
                </label>
                <p className="field-hint">
                  При липса на потвърдена MFA политиката връща отказ. Проверката
                  използва MFA статуса, подаден от системата за удостоверяване.
                </p>
              </>
            )}
            <label className="check-row">
              <input
                type="checkbox"
                checked={draft.enabled}
                onChange={(event) => update("enabled", event.target.checked)}
              />
              <span>Правилото е активно</span>
            </label>
          </fieldset>
          <div className="form-footer">
            <button
              type="button"
              className="secondary"
              disabled={busy}
              onClick={close}
            >
              Отказ
            </button>
            <button type="submit" className="primary" disabled={busy}>
              {busy
                ? "Запазване…"
                : editor.id
                  ? "Запази промените"
                  : "Създай правило"}
            </button>
          </div>
        </form>
      )}
    </Drawer>
  );
}

function CategoryPanel({ rules, onSelect, onCreate }) {
  const categories = [
    ...new Set(rules.map((rule) => rule.category || "")),
  ].sort((a, b) => a.localeCompare(b, "bg"));
  return (
    <Panel
      title="Категории на сайтовете"
      description="Преглед на групите правила и приложените действия. Изберете категория, за да отворите нейните правила."
    >
      {categories.length ? (
        <div className="console-card-grid">
          {categories.map((category) => {
            const members = rules.filter(
              (rule) => (rule.category || "") === category,
            );
            const active = members.filter((rule) => rule.enabled);
            return (
              <button
                type="button"
                className="category-card"
                key={category || "uncategorized"}
                onClick={() => onSelect(category)}
              >
                <span className="category-card-heading">
                  <Globe size={18} />
                  <strong>{category || "Без категория"}</strong>
                  <ArrowRight size={16} />
                </span>
                <span className="category-card-count">
                  {formatNumber(members.length)} <small>правила</small>
                </span>
                <span className="cell-subtitle">
                  {active.length} активни ·{" "}
                  {formatNumber(
                    members.reduce(
                      (sum, rule) => sum + (rule.hit_count || 0),
                      0,
                    ),
                  )}{" "}
                  съвпадения
                </span>
                <span className="category-card-footer">
                  <span>
                    {active.filter((rule) => rule.action === "block").length}{" "}
                    блокиращи
                  </span>
                  <span>
                    {active.filter((rule) => rule.action === "allow").length}{" "}
                    разрешаващи
                  </span>
                  <span>
                    {active.filter((rule) => rule.action === "review").length}{" "}
                    за преглед
                  </span>
                </span>
              </button>
            );
          })}
        </div>
      ) : (
        <div className="empty-state">
          <Globe size={28} />
          <h3>Няма категории</h3>
          <p>
            Задайте категория при създаване на правило, за да организирате
            политиките за сайтове.
          </p>
          <button type="button" className="primary" onClick={onCreate}>
            <Plus size={16} />
            Ново правило
          </button>
        </div>
      )}
    </Panel>
  );
}

function PolicyProbe({ moduleKey, rules, users, onEdit }) {
  const config = POLICY_CONFIG[moduleKey];
  const isWeb = moduleKey === "web_filter";
  const [probe, setProbe] = useState(
    isWeb
      ? { url: "", source_ip: "" }
      : {
          username: "",
          group: "",
          source_ip: "",
          network_type: "vpn",
          mfa_verified: false,
        },
  );
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState(null);
  const [testedAt, setTestedAt] = useState(null);
  useEffect(() => {
    setResult(null);
  }, [rules]);
  const update = (key, value) => {
    setProbe((current) => ({ ...current, [key]: value }));
    setResult(null);
    setMessage(null);
  };

  async function evaluate(event) {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setMessage(null);
    setResult(null);
    try {
      const body = Object.fromEntries(
        Object.entries(probe)
          .map(([key, value]) => [
            key,
            typeof value === "string" ? value.trim() : value,
          ])
          .filter(([, value]) => value !== ""),
      );
      const response = await apiPost(`${config.endpoint}/evaluate/`, body);
      setResult(response);
      setTestedAt(new Date().toISOString());
    } catch (error) {
      setMessage({ tone: "danger", text: error.message });
    } finally {
      setBusy(false);
    }
  }

  const groups = [
    ...new Set(
      rules
        .map((rule) => rule.group)
        .filter((group) => group && !["any", "*"].includes(group)),
    ),
  ];
  return (
    <div className="console-split">
      <Panel
        title={config.testTitle}
        description="Симулация на текущата политика без запис на събитие и без промяна на броячите."
      >
        <Notice message={message} onClose={() => setMessage(null)} />
        <form className="drawer-form" onSubmit={evaluate}>
          <fieldset disabled={busy} className="console-fieldset">
            {isWeb ? (
              <Field label="URL адрес">
                <input
                  autoFocus
                  required
                  type="url"
                  maxLength={2048}
                  value={probe.url}
                  onChange={(event) => update("url", event.target.value)}
                  placeholder="https://example.com/page"
                />
              </Field>
            ) : (
              <>
                <Field label="Потребител">
                  <input
                    autoFocus
                    required
                    maxLength={150}
                    list="policy-probe-users"
                    value={probe.username}
                    onChange={(event) => update("username", event.target.value)}
                    placeholder="ivan.petrov"
                  />
                  <datalist id="policy-probe-users">
                    {users.map((user) => (
                      <option key={user.id} value={user.username} />
                    ))}
                  </datalist>
                </Field>
                <div className="form-grid">
                  <Field
                    label="Група"
                    hint="Групата е входно условие за проверката."
                  >
                    <input
                      list="policy-probe-groups"
                      maxLength={140}
                      value={probe.group}
                      onChange={(event) => update("group", event.target.value)}
                      placeholder="employees"
                    />
                    <datalist id="policy-probe-groups">
                      {groups.map((group) => (
                        <option key={group} value={group} />
                      ))}
                    </datalist>
                  </Field>
                  <Field label="Тип връзка">
                    <select
                      value={probe.network_type}
                      onChange={(event) =>
                        update("network_type", event.target.value)
                      }
                    >
                      <SelectOptions
                        options={NETWORKS.filter(([key]) => key !== "any")}
                      />
                    </select>
                  </Field>
                </div>
              </>
            )}
            <Field
              label="IP адрес на източника"
              hint="Незадължителен контекст за проверката."
            >
              <input
                className="mono"
                value={probe.source_ip}
                onChange={(event) => update("source_ip", event.target.value)}
                placeholder="10.0.0.40"
              />
            </Field>
            {!isWeb && (
              <label className="check-row">
                <input
                  type="checkbox"
                  checked={probe.mfa_verified}
                  onChange={(event) =>
                    update("mfa_verified", event.target.checked)
                  }
                />
                <span>MFA е потвърдена</span>
              </label>
            )}
          </fieldset>
          {!isWeb && (
            <div className="console-callout">
              Проверката оценява подадения MFA статус. Тя не удостоверява
              потребителя и не създава сесия.
            </div>
          )}
          <div className="form-footer">
            <button type="submit" className="primary" disabled={busy}>
              <Play size={16} />
              {busy ? "Проверка…" : "Изпълни проверка"}
            </button>
          </div>
        </form>
      </Panel>
      <Panel
        title="Резултат от проверката"
        description={
          testedAt && result
            ? `Проверено ${formatDate(testedAt)}`
            : "Решение, съвпадащо правило и приложени условия."
        }
      >
        {result ? (
          <ProbeResult result={result} moduleKey={moduleKey} onEdit={onEdit} />
        ) : (
          <div className="empty-state">
            <ShieldCheck size={32} />
            <h3>{busy ? "Оценяване на политиката…" : "Готово за проверка"}</h3>
            <p>
              Попълнете условията и изпълнете проверка, за да видите как
              текущата конфигурация определя решението.
            </p>
          </div>
        )}
      </Panel>
    </div>
  );
}

function ProbeResult({ result, moduleKey, onEdit }) {
  const config = POLICY_CONFIG[moduleKey];
  const isWeb = moduleKey === "web_filter";
  const verdict = result[config.verdictKey];
  const policyVerdict =
    result[isWeb ? "policy_action" : "policy_effect"] || verdict;
  const matched = result.matched_rule;
  const reason =
    {
      module_disabled:
        "Модулът е изключен. Заявката не е ограничена от тази политика.",
      monitor_only:
        "Модулът е в режим на наблюдение. Решението на политиката е показано по-долу, а заявката се разрешава.",
      mfa_required:
        "Политиката изисква MFA, но за тази проверка не е подадено потвърждение.",
      matched_rule:
        "Приложено е първото активно правило, което съвпада с подадените условия.",
      default_policy:
        "Няма съвпадащо активно правило. Използва се действието по подразбиране.",
    }[result.reason] ||
    (matched
      ? "Намерено е съвпадащо активно правило."
      : "Няма съвпадащо правило. Използва се действието по подразбиране.");

  return (
    <div className="console-result">
      <div className="console-result-heading">
        <span className="cell-subtitle">Ефективно решение</span>
        <StatusBadge
          value={verdict}
          label={labelFor(config.actions, verdict)}
        />
      </div>
      <p>{reason}</p>
      <dl className="detail-grid">
        <div>
          <dt>Решение на политиката</dt>
          <dd>
            <StatusBadge
              value={policyVerdict}
              label={labelFor(config.actions, policyVerdict)}
            />
          </dd>
        </div>
        <div>
          <dt>Режим</dt>
          <dd>
            {result.module_enabled === false || result.mode === "disabled"
              ? "Изключен"
              : result.mode === "monitor"
                ? "Наблюдение"
                : "Прилагане"}
          </dd>
        </div>
        <div>
          <dt>Съвпадащо правило</dt>
          <dd>{matched?.name || "Няма съвпадение"}</dd>
        </div>
        <div>
          <dt>Приоритет</dt>
          <dd>{matched?.priority ?? "—"}</dd>
        </div>
        {isWeb ? (
          <>
            <div>
              <dt>Условие</dt>
              <dd className="mono">{matched?.pattern || "—"}</dd>
            </div>
            <div>
              <dt>Категория</dt>
              <dd>{result.category || "Без категория"}</dd>
            </div>
          </>
        ) : (
          <>
            <div>
              <dt>Изискване за MFA</dt>
              <dd>{result.mfa_required ? "Задължителна" : "Не се изисква"}</dd>
            </div>
            <div>
              <dt>Подаден MFA статус</dt>
              <dd>
                <StatusBadge
                  value={result.mfa_verified ? "healthy" : "warning"}
                  label={result.mfa_verified ? "Потвърдена" : "Непотвърдена"}
                />
              </dd>
            </div>
          </>
        )}
      </dl>
      {matched && (
        <button
          type="button"
          className="secondary"
          onClick={() => onEdit(matched)}
        >
          <Pencil size={15} />
          Отвори правилото
        </button>
      )}
    </div>
  );
}

function PolicyEvents({ moduleKey, events, onSelect }) {
  const isWeb = moduleKey === "web_filter";
  const config = POLICY_CONFIG[moduleKey];
  return (
    <Panel
      title={isWeb ? "Събития за интернет достъп" : "Събития за достъп"}
      description="Последни заредени събития от модула. Тестовите проверки не се записват в журнала."
    >
      <DataTable
        rows={events}
        exportName={`${moduleKey}-events`}
        onRowClick={onSelect}
        searchPlaceholder={
          isWeb
            ? "Търси URL, IP или съобщение…"
            : "Търси потребител, IP или съобщение…"
        }
        emptyTitle="Няма записани събития"
        emptyDescription="Тук ще се показват реалните решения, записани от модула."
        filters={[
          { key: "action", label: "Решение", options: config.actions },
          {
            key: "severity",
            label: "Важност",
            options: [
              ["low", "Ниска"],
              ["medium", "Средна"],
              ["high", "Висока"],
              ["critical", "Критична"],
            ],
          },
        ]}
        columns={[
          {
            key: "occurred_at",
            label: "Време",
            render: (event) => formatDate(event.occurred_at),
          },
          {
            key: "source_ip",
            label: "Източник",
            render: (event) => <span className="mono">{event.source_ip}</span>,
          },
          {
            key: isWeb ? "destination" : "username",
            label: isWeb ? "URL / дестинация" : "Потребител",
            render: (event) => (
              <>
                <span className="cell-title">
                  {(isWeb ? event.destination : event.username) || "—"}
                </span>
                <span className="cell-subtitle">{event.event_type}</span>
              </>
            ),
          },
          {
            key: "action",
            label: "Решение",
            render: (event) => (
              <StatusBadge
                value={event.action}
                label={labelFor(config.actions, event.action)}
              />
            ),
          },
          {
            key: "severity",
            label: "Важност",
            render: (event) => <StatusBadge value={event.severity} />,
          },
          { key: "message", label: "Съобщение" },
        ]}
      />
    </Panel>
  );
}

function EventDetails({ event, isWeb, onClose }) {
  const extra = event.extra_data || {};
  return (
    <Drawer
      title="Детайли за събитието"
      description={`Събитие #${event.id} · ${formatDate(event.occurred_at)}`}
      onClose={onClose}
    >
      <dl className="detail-grid">
        <div>
          <dt>Тип</dt>
          <dd>{event.event_type}</dd>
        </div>
        <div>
          <dt>Важност</dt>
          <dd>
            <StatusBadge value={event.severity} />
          </dd>
        </div>
        <div>
          <dt>IP на източника</dt>
          <dd className="mono">{event.source_ip}</dd>
        </div>
        <div>
          <dt>Действие</dt>
          <dd>
            <StatusBadge value={extra.action} />
          </dd>
        </div>
        <div>
          <dt>{isWeb ? "URL / дестинация" : "Потребител"}</dt>
          <dd className="mono">
            {isWeb
              ? extra.url || event.destination
              : extra.username || event.destination}
          </dd>
        </div>
        {!isWeb && (
          <>
            <div>
              <dt>Група</dt>
              <dd>{extra.group || "—"}</dd>
            </div>
            <div>
              <dt>Връзка</dt>
              <dd>{labelFor(NETWORKS, extra.network_type)}</dd>
            </div>
            <div>
              <dt>MFA</dt>
              <dd>
                {extra.mfa_verified == null
                  ? "Няма данни"
                  : extra.mfa_verified
                    ? "Потвърдена"
                    : "Непотвърдена"}
              </dd>
            </div>
          </>
        )}
      </dl>
      <Field label="Съобщение">
        <p className="console-callout">
          {event.message || "Няма допълнително съобщение."}
        </p>
      </Field>
    </Drawer>
  );
}

const blankUser = () => ({
  username: "",
  password: "",
  email: "",
  first_name: "",
  last_name: "",
  is_staff: false,
  is_active: true,
});

function LocalUsers({ users, currentUser, onReload }) {
  const [editor, setEditor] = useState(null);
  const [pendingStatus, setPendingStatus] = useState(null);
  const [message, setMessage] = useState(null);
  const [busy, setBusy] = useState(false);
  const isAdmin = Boolean(currentUser?.is_staff);

  function edit(user) {
    setEditor({
      id: user.id,
      draft: {
        username: user.username,
        email: user.email || "",
        first_name: user.first_name || "",
        last_name: user.last_name || "",
        is_staff: user.is_staff,
        is_active: user.is_active,
        password: "",
      },
    });
  }

  async function changeStatus() {
    if (busy || !pendingStatus) return;
    setBusy(true);
    setMessage(null);
    try {
      await apiPatch(`/auth/users/${pendingStatus.id}/`, {
        is_active: !pendingStatus.is_active,
      });
      await onReload();
      setMessage({
        tone: "ok",
        text: `Акаунтът „${pendingStatus.username}“ е ${pendingStatus.is_active ? "деактивиран" : "активиран"}.`,
      });
      setPendingStatus(null);
    } catch (error) {
      setMessage({ tone: "danger", text: error.message });
      setPendingStatus(null);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Panel
      title="Локални потребители"
      description="Акаунти за вход в конзолата. Групите в политиките за мрежов достъп се подават отделно от системата за удостоверяване."
      actions={
        isAdmin ? (
          <button
            type="button"
            className="primary"
            onClick={() => setEditor({ id: null, draft: blankUser() })}
          >
            <Plus size={16} />
            Нов потребител
          </button>
        ) : (
          <StatusBadge value="monitor" label="Само преглед" />
        )
      }
    >
      <Notice message={message} onClose={() => setMessage(null)} />
      <DataTable
        rows={users}
        exportName="local-users"
        searchPlaceholder="Търси потребител, име или имейл…"
        emptyTitle="Няма потребители"
        emptyDescription="Локалните акаунти ще се показват тук."
        filters={[
          {
            key: "is_active",
            label: "Състояние",
            options: [
              ["true", "Активни"],
              ["false", "Неактивни"],
            ],
          },
          {
            key: "is_staff",
            label: "Роля",
            options: [
              ["true", "Администратори"],
              ["false", "Оператори"],
            ],
          },
        ]}
        columns={[
          {
            key: "username",
            label: "Потребител",
            searchValue: (user) =>
              `${user.username} ${user.first_name} ${user.last_name}`,
            render: (user) => (
              <>
                <span className="cell-title">
                  {user.username}
                  {user.id === currentUser?.id ? " (вие)" : ""}
                </span>
                <span className="cell-subtitle">
                  {[user.first_name, user.last_name]
                    .filter(Boolean)
                    .join(" ") || "Без въведено име"}
                </span>
              </>
            ),
          },
          { key: "email", label: "Имейл", render: (user) => user.email || "—" },
          {
            key: "is_staff",
            label: "Роля",
            render: (user) => (
              <StatusBadge
                value={user.is_staff ? "monitor" : "disabled"}
                label={user.is_staff ? "Администратор" : "Оператор"}
              />
            ),
          },
          {
            key: "is_active",
            label: "Състояние",
            render: (user) => (
              <StatusBadge
                value={user.is_active ? "healthy" : "disabled"}
                label={user.is_active ? "Активен" : "Неактивен"}
              />
            ),
          },
          {
            key: "last_login",
            label: "Последен вход",
            render: (user) =>
              user.last_login ? formatDate(user.last_login) : "Все още няма",
          },
          {
            key: "date_joined",
            label: "Създаден",
            render: (user) => formatDate(user.date_joined),
          },
          ...(isAdmin
            ? [
                {
                  key: "actions",
                  label: "Действия",
                  render: (user) => (
                    <div className="table-actions">
                      <button
                        type="button"
                        className="icon-button"
                        title="Редактирай потребител"
                        aria-label={`Редактирай ${user.username}`}
                        onClick={() => edit(user)}
                      >
                        <Pencil size={15} />
                      </button>
                      <button
                        type="button"
                        className="secondary compact"
                        disabled={busy || user.id === currentUser?.id}
                        title={
                          user.id === currentUser?.id
                            ? "Не можете да деактивирате собствения си акаунт"
                            : undefined
                        }
                        onClick={() => setPendingStatus(user)}
                      >
                        {user.is_active ? "Деактивирай" : "Активирай"}
                      </button>
                    </div>
                  ),
                },
              ]
            : []),
        ]}
      />
      {editor && (
        <UserEditor
          key={editor.id || "new-user"}
          editor={editor}
          currentUser={currentUser}
          onClose={() => setEditor(null)}
          onSaved={async () => {
            setEditor(null);
            await onReload();
            setMessage({
              tone: "ok",
              text: editor.id
                ? "Потребителят е обновен."
                : "Потребителят е създаден.",
            });
          }}
        />
      )}
      {pendingStatus && (
        <ConfirmDialog
          title={
            pendingStatus.is_active
              ? "Деактивиране на акаунт"
              : "Активиране на акаунт"
          }
          description={
            pendingStatus.is_active
              ? `„${pendingStatus.username}“ ще загуби достъп до конзолата. Акаунтът и неговите данни ще бъдат запазени.`
              : `„${pendingStatus.username}“ ще може отново да влиза в конзолата с текущите си права.`
          }
          busy={busy}
          onClose={() => {
            if (!busy) setPendingStatus(null);
          }}
          onConfirm={changeStatus}
        />
      )}
    </Panel>
  );
}

function UserEditor({ editor, currentUser, onClose, onSaved }) {
  const [draft, setDraft] = useState(editor.draft);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState(null);
  const [discarding, setDiscarding] = useState(false);
  const dirty = JSON.stringify(draft) !== JSON.stringify(editor.draft);
  useDraftGuard("policy-user", dirty || busy);
  const close = () => {
    if (!busy) {
      if (dirty) setDiscarding(true);
      else onClose();
    }
  };
  const self = editor.id === currentUser?.id;
  const update = (key, value) =>
    setDraft((current) => ({ ...current, [key]: value }));

  async function save(event) {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setMessage(null);
    const body = {
      ...draft,
      username: draft.username.trim(),
      email: draft.email.trim(),
      first_name: draft.first_name.trim(),
      last_name: draft.last_name.trim(),
    };
    if (editor.id && !body.password) delete body.password;
    try {
      if (!body.username) throw new Error("Въведете потребителско име.");
      if (editor.id) await apiPatch(`/auth/users/${editor.id}/`, body);
      else await apiPost("/auth/users/", body);
      await onSaved();
    } catch (error) {
      setMessage({ tone: "danger", text: error.message });
    } finally {
      setBusy(false);
    }
  }

  return (
    <Drawer
      title={
        discarding
          ? "Незапазени промени"
          : editor.id
            ? "Редактиране на потребител"
            : "Нов потребител"
      }
      description="Локален акаунт за достъп до административната конзола."
      onClose={close}
    >
      {discarding ? (
        <DiscardChanges
          onKeep={() => setDiscarding(false)}
          onDiscard={onClose}
        />
      ) : (
        <form className="drawer-form" onSubmit={save}>
          <Notice message={message} onClose={() => setMessage(null)} />
          <fieldset className="console-fieldset" disabled={busy}>
            <Field label="Потребителско име">
              <input
                autoFocus
                autoComplete="off"
                required
                maxLength={150}
                value={draft.username}
                onChange={(event) => update("username", event.target.value)}
              />
            </Field>
            <div className="form-grid">
              <Field label="Име">
                <input
                  maxLength={150}
                  autoComplete="given-name"
                  value={draft.first_name}
                  onChange={(event) => update("first_name", event.target.value)}
                />
              </Field>
              <Field label="Фамилия">
                <input
                  maxLength={150}
                  autoComplete="family-name"
                  value={draft.last_name}
                  onChange={(event) => update("last_name", event.target.value)}
                />
              </Field>
            </div>
            <Field label="Имейл">
              <input
                type="email"
                maxLength={254}
                autoComplete="email"
                value={draft.email}
                onChange={(event) => update("email", event.target.value)}
              />
            </Field>
            <Field
              label={editor.id ? "Нова парола" : "Парола"}
              hint={
                editor.id
                  ? "Оставете празно, за да запазите текущата парола. Минимум 8 символа."
                  : "Минимум 8 символа. Използвайте уникална парола за този акаунт."
              }
            >
              <input
                type="password"
                autoComplete="new-password"
                required={!editor.id}
                minLength={8}
                value={draft.password}
                onChange={(event) => update("password", event.target.value)}
              />
            </Field>
            <Field
              label="Роля"
              hint={
                self
                  ? "Не можете да премахнете собствените си административни права."
                  : "Администраторите могат да създават и управляват локални потребители."
              }
            >
              <select
                disabled={self}
                value={draft.is_staff ? "admin" : "operator"}
                onChange={(event) =>
                  update("is_staff", event.target.value === "admin")
                }
              >
                <option value="operator">Оператор</option>
                <option value="admin">Администратор</option>
              </select>
            </Field>
            <label className="check-row">
              <input
                type="checkbox"
                disabled={self}
                checked={draft.is_active}
                onChange={(event) => update("is_active", event.target.checked)}
              />
              <span>Акаунтът е активен</span>
            </label>
          </fieldset>
          <div className="form-footer">
            <button
              type="button"
              className="secondary"
              disabled={busy}
              onClick={close}
            >
              Отказ
            </button>
            <button type="submit" className="primary" disabled={busy}>
              <Users size={16} />
              {busy
                ? "Запазване…"
                : editor.id
                  ? "Запази промените"
                  : "Създай потребител"}
            </button>
          </div>
        </form>
      )}
    </Drawer>
  );
}
