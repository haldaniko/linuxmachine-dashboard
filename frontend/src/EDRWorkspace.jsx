import { useEffect, useState } from "react";
import { ArrowRight, Loader2, Plus, Save, Server, Shield } from "lucide-react";
import {
  apiGet,
  apiPost,
  apiRequest,
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
} from "./ConsoleUI";

const severities = [
  ["critical", "Критична"],
  ["high", "Висока"],
  ["medium", "Средна"],
  ["low", "Ниска"],
  ["informational", "Информация"],
];
const threatStates = [
  ["new", "Нова"],
  ["investigating", "Разследва се"],
  ["resolved", "Решена"],
  ["ignored", "Игнорирана"],
  ["blocked", "Блокирана"],
];
const severityFilter = {
  key: "severity",
  label: "Всички нива на риск",
  options: severities,
};
const value = (number) => (number == null ? "—" : formatNumber(number));
const detail = (label, content) => (
  <div key={label}>
    <dt>{label}</dt>
    <dd>{content || "—"}</dd>
  </div>
);

function useDirty(key, dirty) {
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

const eventColumns = [
  {
    key: "title",
    label: "Събитие",
    render: (row) => (
      <>
        <strong>{row.title}</strong>
        <span className="cell-subtitle">
          {row.category} · {row.source}
        </span>
      </>
    ),
  },
  {
    key: "severity",
    label: "Важност",
    render: (row) => <StatusBadge value={row.severity} />,
  },
  { key: "endpoint_hostname", label: "Устройство" },
  {
    key: "source_ip",
    label: "IP източник",
    render: (row) => <span className="mono">{row.source_ip || "—"}</span>,
  },
  { key: "process_name", label: "Процес" },
  {
    key: "timestamp",
    label: "Време",
    render: (row) => formatDate(row.timestamp),
  },
];
const vulnerabilityColumns = [
  {
    key: "cve",
    label: "Уязвимост",
    render: (row) => <strong className="mono">{row.cve}</strong>,
  },
  {
    key: "severity",
    label: "Важност",
    render: (row) => <StatusBadge value={row.severity} />,
  },
  { key: "endpoint_hostname", label: "Устройство" },
  { key: "package", label: "Пакет" },
  { key: "installed_version", label: "Инсталирана версия" },
  { key: "fixed_version", label: "Коригирана версия" },
  {
    key: "status",
    label: "Състояние",
    render: (row) => <StatusBadge value={row.status} />,
  },
];

export function EDRWorkspace({ data, actions }) {
  const status = data.edrStatus || {};
  const endpoints = data.edrEndpoints || [];
  const events = data.edrEvents || [];
  const threats = data.edrThreats || [];
  const vulnerabilities = data.edrVulnerabilities || [];
  const [tab, setTab] = useState("overview");
  const [selectedEndpoint, setSelectedEndpoint] = useState(null);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [adding, setAdding] = useState(false);
  const [message, setMessage] = useState(null);
  const [busy, setBusy] = useState(false);
  const [confirmation, setConfirmation] = useState(null);
  const activeThreats = threats.filter((item) =>
    ["new", "investigating"].includes(item.status),
  );
  const run = async (operation, success) => {
    if (busy) return false;
    setBusy(true);
    setMessage(null);
    try {
      await operation();
      await actions.reload();
      setMessage({ tone: "ok", text: success });
      setConfirmation(null);
      return true;
    } catch (error) {
      setConfirmation(null);
      setMessage({ tone: "danger", text: error.message });
      return false;
    } finally {
      setBusy(false);
    }
  };
  const changeThreat = (row, next) =>
    setConfirmation({
      title: "Промяна на статуса на заплахата",
      description:
        row.title +
        " → " +
        threatStates.find(([key]) => key === next)[1] +
        ". Статусът документира разследването; не изпълнява действия върху устройството.",
      execute: () =>
        run(
          () =>
            apiRequest("/edr/threats/" + row.id + "/status/", {
              method: "PUT",
              body: JSON.stringify({ status: next }),
            }),
          "Статусът на заплахата е обновен.",
        ),
    });
  const blockIp = (event) =>
    setConfirmation({
      title: "Създаване на правило за блокиране",
      description:
        "IP " +
        (event.source_ip || event.destination_ip) +
        " ще бъде добавен като правило във Firewall. Прилагането към мрежата се извършва отделно от модула Firewall.",
      execute: () =>
        run(
          () => apiPost("/edr/events/" + event.id + "/block-ip/", {}),
          "Правилото е създадено във Firewall. Прегледайте го и го приложете от модула Firewall.",
        ),
    });
  const endpointColumns = [
    {
      key: "hostname",
      label: "Устройство",
      render: (row) => (
        <>
          <strong>{row.hostname}</strong>
          <span className="cell-subtitle">{row.ip}</span>
        </>
      ),
    },
    {
      key: "os",
      label: "Операционна система",
      render: (row) => (
        <>
          {row.os || "Не е посочена"}
          <span className="cell-subtitle">{row.os_version}</span>
        </>
      ),
    },
    {
      key: "status",
      label: "Агент",
      render: (row) => <StatusBadge value={row.status} />,
    },
    {
      key: "security_status",
      label: "Състояние",
      render: (row) => (
        <StatusBadge
          value={row.last_seen ? row.security_status : "unknown"}
          label={row.last_seen ? undefined : "Няма телеметрия"}
        />
      ),
    },
    { key: "threats_count", label: "Заплахи" },
    { key: "vulnerabilities_count", label: "CVE" },
    {
      key: "last_seen",
      label: "Последна връзка",
      render: (row) => formatDate(row.last_seen),
    },
  ];
  return (
    <ModuleFrame
      eyebrow="ЗАЩИТА НА КРАЙНИ УСТРОЙСТВА"
      title="EDR"
      description="Състояние на агентите, разследване на събития и проследяване на уязвимости."
      status={
        <StatusBadge
          value={status.online > 0 ? "online" : "unknown"}
          label={
            status.online > 0 ? "Има свързани агенти" : "Няма онлайн агенти"
          }
        />
      }
      actions={
        <button className="primary" onClick={() => setAdding(true)}>
          <Plus size={16} />
          Добави устройство
        </button>
      }
      metrics={[
        {
          label: "Устройства",
          value: value(status.endpoints),
          hint: "Регистрирани в инвентара",
        },
        {
          label: "Онлайн агенти",
          value: value(status.online),
          hint: value(status.offline) + " офлайн",
        },
        {
          label: "Заплахи за 24 часа",
          value: value(status.threats_24h),
          hint: activeThreats.length + " чакат обработка",
          tone: status.threats_24h ? "danger" : "",
        },
        {
          label: "Уязвими устройства",
          value: value(status.vulnerable_endpoints),
          hint: "С отворени CVE",
          tone: status.vulnerable_endpoints ? "warn" : "",
        },
      ]}
    >
      <Notice message={message} onClose={() => setMessage(null)} />
      <Tabs
        value={tab}
        onChange={setTab}
        items={[
          { key: "overview", label: "Преглед" },
          { key: "endpoints", label: "Устройства", count: endpoints.length },
          { key: "events", label: "Събития" },
          { key: "threats", label: "Заплахи", count: activeThreats.length },
          { key: "vulnerabilities", label: "Уязвимости" },
          { key: "metrics", label: "Интеграции" },
          { key: "settings", label: "Настройки" },
        ]}
      />
      {tab === "overview" && (
        <>
          <div className="console-grid">
            <Panel
              title="Покритие на устройствата"
              description="Изчислено от последната получена телеметрия."
            >
              <div className="summary-card">
                <strong>
                  {endpoints.length
                    ? Math.round(
                        (endpoints.filter((item) => item.status === "online")
                          .length /
                          endpoints.length) *
                          100,
                      ) + "%"
                    : "—"}
                </strong>
                <p>от регистрираните устройства са онлайн</p>
                <div className="progress-track">
                  <span
                    style={{
                      width: endpoints.length
                        ? (endpoints.filter((item) => item.status === "online")
                            .length /
                            endpoints.length) *
                            100 +
                          "%"
                        : "0%",
                    }}
                  />
                </div>
              </div>
              <ul className="health-list">
                <li>
                  <span>Без връзка с агента</span>
                  <strong>{value(status.offline)}</strong>
                </li>
                <li>
                  <span>Никога не са се свързвали</span>
                  <strong>{value(status.never_connected)}</strong>
                </li>
                <li>
                  <span>Последно събитие</span>
                  <span>{formatDate(status.last_event)}</span>
                </li>
              </ul>
            </Panel>
            <Panel
              title="Приоритет за разследване"
              description="Събитията и заплахите са различни записи."
            >
              <ul className="health-list">
                <li>
                  <span>Критични събития · 24 ч.</span>
                  <StatusBadge
                    value={status.critical_24h ? "critical" : "neutral"}
                    label={value(status.critical_24h)}
                  />
                </li>
                <li>
                  <span>Събития с висок риск · 24 ч.</span>
                  <strong>{value(status.high_24h)}</strong>
                </li>
                <li>
                  <span>Нови заплахи</span>
                  <strong>
                    {threats.filter((item) => item.status === "new").length}
                  </strong>
                </li>
                <li>
                  <span>Разследвания в ход</span>
                  <strong>
                    {
                      threats.filter((item) => item.status === "investigating")
                        .length
                    }
                  </strong>
                </li>
                <li>
                  <span>Опашка за обработка</span>
                  <button
                    className="secondary"
                    onClick={() => setTab("threats")}
                  >
                    Отвори заплахите
                    <ArrowRight size={14} />
                  </button>
                </li>
              </ul>
            </Panel>
          </div>
          <Panel
            title="Последни събития"
            description="Най-новите 10 записа от свързаните източници."
            actions={
              <button className="secondary" onClick={() => setTab("events")}>
                Всички събития
                <ArrowRight size={14} />
              </button>
            }
          >
            <DataTable
              rows={events.slice(0, 10)}
              columns={eventColumns}
              onRowClick={setSelectedEvent}
              emptyTitle="Все още няма телеметрия"
              emptyDescription="След свързване на източник тук ще се появят събитията от устройствата."
            />
          </Panel>
        </>
      )}
      {tab === "endpoints" && (
        <Panel
          title="Инвентар на устройствата"
          description="Отворете устройство, за да разгледате неговите събития и уязвимости."
        >
          <DataTable
            rows={endpoints}
            columns={endpointColumns}
            onRowClick={setSelectedEndpoint}
            exportName="edr-devices"
            searchPlaceholder="Име, IP адрес или операционна система…"
            filters={[
              {
                key: "status",
                label: "Всички агенти",
                options: [
                  ["online", "Онлайн"],
                  ["offline", "Офлайн"],
                  ["never_connected", "Не са свързвани"],
                  ["error", "Грешка"],
                ],
              },
              {
                key: "security_status",
                label: "Всички състояния",
                options: [
                  ["protected", "Защитени"],
                  ["attention", "Внимание"],
                  ["at_risk", "В риск"],
                  ["critical", "Критични"],
                ],
              },
            ]}
            emptyTitle="Инвентарът е празен"
            emptyDescription="Добавете устройство в инвентара или свържете източник на телеметрия."
          />
        </Panel>
      )}
      {tab === "events" && (
        <Panel
          title="Събития за сигурност"
          description="Последните до 1 000 събития. Отворете запис за пълния контекст."
        >
          <DataTable
            rows={events}
            columns={eventColumns}
            onRowClick={setSelectedEvent}
            filters={[severityFilter]}
            searchPlaceholder="Събитие, устройство, процес или IP…"
            exportName="edr-events"
          />
        </Panel>
      )}
      {tab === "threats" && (
        <Panel
          title="Управление на заплахи"
          description="Следете жизнения цикъл на разследването. Промяната на статус не изпълнява команда върху агента."
        >
          <DataTable
            rows={threats}
            columns={[
              {
                key: "title",
                label: "Заплаха",
                render: (row) => (
                  <>
                    <strong>{row.title}</strong>
                    <span className="cell-subtitle">{row.category}</span>
                  </>
                ),
              },
              { key: "endpoint_hostname", label: "Устройство" },
              {
                key: "severity",
                label: "Важност",
                render: (row) => <StatusBadge value={row.severity} />,
              },
              {
                key: "status",
                label: "Статус",
                render: (row) => (
                  <select
                    aria-label={"Статус на " + row.title}
                    value={row.status}
                    disabled={busy}
                    onChange={(event) => changeThreat(row, event.target.value)}
                  >
                    {threatStates.map(([key, label]) => (
                      <option value={key} key={key}>
                        {label}
                      </option>
                    ))}
                  </select>
                ),
              },
              {
                key: "updated_at",
                label: "Последна промяна",
                render: (row) => formatDate(row.updated_at),
              },
            ]}
            onRowClick={(row) => {
              const event = events.find((item) => item.id === row.event);
              if (event) setSelectedEvent(event);
              else {
                setBusy(true);
                apiGet("/edr/events/" + row.event + "/")
                  .then(setSelectedEvent)
                  .catch((error) =>
                    setMessage({ tone: "danger", text: error.message }),
                  )
                  .finally(() => setBusy(false));
              }
            }}
            filters={[
              severityFilter,
              { key: "status", label: "Всички статуси", options: threatStates },
            ]}
            exportName="edr-threats"
            emptyTitle="Няма регистрирани заплахи"
            emptyDescription="Тук се проследяват заплахите, създадени от получените събития."
          />
        </Panel>
      )}
      {tab === "vulnerabilities" && (
        <Panel
          title="Уязвимости и актуализации"
          description="Версиите с корекция се показват, когато са предоставени от източника."
        >
          <DataTable
            rows={vulnerabilities}
            columns={vulnerabilityColumns}
            filters={[
              severityFilter,
              {
                key: "status",
                label: "Всички статуси",
                options: [
                  ["open", "Отворени"],
                  ["resolved", "Решени"],
                ],
              },
            ]}
            searchPlaceholder="CVE, пакет или устройство…"
            exportName="edr-vulnerabilities"
          />
        </Panel>
      )}
      {tab === "metrics" && (
        <IntegrationMetrics
          metrics={data.crowdsecMetrics}
          onRefresh={actions.reload}
        />
      )}
      <div hidden={tab !== "settings"}>
        <EDRSettings setting={data.edrSettings} onReload={actions.reload} />
      </div>
      {adding && (
        <EndpointEditor
          onClose={() => setAdding(false)}
          onSaved={async () => {
            setAdding(false);
            await actions.reload();
            setMessage({
              tone: "ok",
              text: "Устройството е добавено в инвентара. Очаква се първа връзка от агента.",
            });
          }}
        />
      )}
      {selectedEndpoint && (
        <EndpointDetails
          endpoint={
            endpoints.find((item) => item.id === selectedEndpoint.id) ||
            selectedEndpoint
          }
          onClose={() => setSelectedEndpoint(null)}
          onEvent={(event) => {
            setSelectedEndpoint(null);
            setSelectedEvent(event);
          }}
        />
      )}
      {selectedEvent && (
        <Drawer
          title={selectedEvent.title}
          description={
            (selectedEvent.endpoint_hostname || "Без устройство") +
            " · " +
            formatDate(selectedEvent.timestamp)
          }
          onClose={() => !busy && setSelectedEvent(null)}
        >
          <div className="console-stack">
            <Notice message={message} />
            <dl className="detail-grid">
              {detail(
                "Важност",
                <StatusBadge value={selectedEvent.severity} />,
              )}
              {detail("Категория", selectedEvent.category)}
              {detail("Потребител", selectedEvent.username)}
              {detail("Процес", selectedEvent.process_name)}
              {detail("Родителски процес", selectedEvent.parent_process)}
              {detail("IP източник", selectedEvent.source_ip)}
              {detail("IP дестинация", selectedEvent.destination_ip)}
              {detail("Действие", <StatusBadge value={selectedEvent.action} />)}
              {detail("Файл", selectedEvent.file_path)}
              {detail("Хеш", selectedEvent.file_hash)}
            </dl>
            {selectedEvent.description && (
              <p className="subtle">{selectedEvent.description}</p>
            )}
            <details className="technical-details">
              <summary>Пълен запис на събитието</summary>
              <pre>
                {JSON.stringify(selectedEvent.raw_event || {}, null, 2)}
              </pre>
            </details>
            <div className="form-footer">
              <button
                className="secondary"
                onClick={() => setSelectedEvent(null)}
                disabled={busy}
              >
                Затвори
              </button>
              <button
                className="primary"
                disabled={
                  busy ||
                  !(selectedEvent.source_ip || selectedEvent.destination_ip)
                }
                onClick={() => blockIp(selectedEvent)}
              >
                <Shield size={15} />
                Създай Firewall правило
              </button>
            </div>
          </div>
        </Drawer>
      )}
      {confirmation && (
        <ConfirmDialog
          title={confirmation.title}
          description={confirmation.description}
          busy={busy}
          onClose={() => setConfirmation(null)}
          onConfirm={confirmation.execute}
        />
      )}
    </ModuleFrame>
  );
}

function EndpointEditor({ onClose, onSaved }) {
  const blank = {
    hostname: "",
    ip: "",
    os: "",
    os_version: "",
    architecture: "",
    agent_id: "",
  };
  const [draft, setDraft] = useState(blank);
  const [message, setMessage] = useState(null);
  const [busy, setBusy] = useState(false);
  const dirty = JSON.stringify(draft) !== JSON.stringify(blank);
  useDirty("edr-endpoint", dirty || busy);
  const close = () => {
    if (!busy && (!dirty || window.confirm("Да отхвърля ли въведените данни?")))
      onClose();
  };
  const save = async (event) => {
    event.preventDefault();
    setBusy(true);
    setMessage(null);
    try {
      await apiPost("/edr/endpoints/", {
        ...draft,
        hostname: draft.hostname.trim(),
        status: "never_connected",
      });
      await onSaved();
    } catch (error) {
      setMessage({ tone: "danger", text: error.message });
    } finally {
      setBusy(false);
    }
  };
  return (
    <Drawer
      title="Добавяне на устройство"
      description="Регистрирайте актив в инвентара. Свързването на агент се извършва през вашата Wazuh инфраструктура."
      onClose={close}
    >
      <form className="drawer-form" onSubmit={save}>
        <Notice message={message} />
        <Field label="Име на устройството">
          <input
            required
            maxLength={160}
            value={draft.hostname}
            onChange={(event) =>
              setDraft({ ...draft, hostname: event.target.value })
            }
            placeholder="workstation-sofia-01"
          />
        </Field>
        <Field label="IP адрес">
          <input
            required
            value={draft.ip}
            onChange={(event) => setDraft({ ...draft, ip: event.target.value })}
            placeholder="192.168.1.20"
          />
        </Field>
        <Field label="Операционна система">
          <input
            value={draft.os}
            maxLength={120}
            onChange={(event) => setDraft({ ...draft, os: event.target.value })}
            placeholder="Windows / Ubuntu / Debian"
          />
        </Field>
        <Field label="Версия на ОС">
          <input
            value={draft.os_version}
            maxLength={120}
            onChange={(event) =>
              setDraft({ ...draft, os_version: event.target.value })
            }
          />
        </Field>
        <Field label="Архитектура">
          <select
            value={draft.architecture}
            onChange={(event) =>
              setDraft({ ...draft, architecture: event.target.value })
            }
          >
            <option value="">Не е посочена</option>
            <option value="x86_64">x86_64</option>
            <option value="arm64">ARM64</option>
            <option value="x86">x86</option>
          </select>
        </Field>
        <Field label="ID на агента (по избор)">
          <input
            value={draft.agent_id}
            maxLength={120}
            onChange={(event) =>
              setDraft({ ...draft, agent_id: event.target.value })
            }
          />
        </Field>
        <div className="form-footer">
          <button
            type="button"
            className="secondary"
            disabled={busy}
            onClick={close}
          >
            Отказ
          </button>
          <button className="primary" disabled={busy}>
            {busy ? <Loader2 className="spin" size={15} /> : <Plus size={15} />}
            Добави устройство
          </button>
        </div>
      </form>
    </Drawer>
  );
}

function EndpointDetails({ endpoint, onClose, onEvent }) {
  const [detailTab, setDetailTab] = useState("events");
  const [events, setEvents] = useState([]);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [message, setMessage] = useState(null);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    let active = true;
    Promise.all([
      apiGet("/edr/endpoints/" + endpoint.id + "/events/"),
      apiGet("/edr/endpoints/" + endpoint.id + "/vulnerabilities/"),
    ])
      .then(([eventRows, vulnerabilityRows]) => {
        if (active) {
          setEvents(eventRows);
          setVulnerabilities(vulnerabilityRows);
        }
      })
      .catch((error) => {
        if (active) setMessage({ tone: "danger", text: error.message });
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [endpoint.id]);
  return (
    <Drawer
      title={endpoint.hostname}
      description={endpoint.ip + " · " + (endpoint.os || "ОС не е посочена")}
      onClose={onClose}
    >
      <div className="console-stack">
        <dl className="detail-grid">
          {detail("Агент", <StatusBadge value={endpoint.status} />)}
          {detail(
            "Състояние",
            <StatusBadge
              value={endpoint.last_seen ? endpoint.security_status : "unknown"}
              label={endpoint.last_seen ? undefined : "Няма телеметрия"}
            />,
          )}
          {detail("ID на агента", endpoint.agent_id)}
          {detail("Версия на агента", endpoint.agent_version)}
          {detail("Архитектура", endpoint.architecture)}
          {detail("Последен потребител", endpoint.logged_in_user)}
          {detail("Първа регистрация", formatDate(endpoint.first_seen))}
          {detail("Последна връзка", formatDate(endpoint.last_seen))}
        </dl>
        <Notice message={message} />
        <Tabs
          value={detailTab}
          onChange={setDetailTab}
          items={[
            { key: "events", label: "Събития", count: events.length },
            {
              key: "vulns",
              label: "Уязвимости",
              count: vulnerabilities.length,
            },
          ]}
        />
        {loading ? (
          <p className="subtle">Зареждане на подробностите…</p>
        ) : detailTab === "events" ? (
          <DataTable
            rows={events}
            columns={eventColumns.filter((column) =>
              ["title", "severity", "timestamp"].includes(column.key),
            )}
            onRowClick={onEvent}
          />
        ) : (
          <DataTable
            rows={vulnerabilities}
            columns={vulnerabilityColumns.filter((column) =>
              ["cve", "severity", "package", "fixed_version"].includes(
                column.key,
              ),
            )}
          />
        )}
      </div>
    </Drawer>
  );
}

function EDRSettings({ setting, onReload }) {
  const makeDraft = () => ({
    manager_url: setting?.settings?.manager_url || "",
    agent_offline_timeout_minutes:
      setting?.settings?.agent_offline_timeout_minutes || 15,
  });
  const [draft, setDraft] = useState(makeDraft);
  const [baseline, setBaseline] = useState(() => JSON.stringify(makeDraft()));
  const [message, setMessage] = useState(null);
  const [busy, setBusy] = useState(false);
  const dirty = JSON.stringify(draft) !== baseline;
  useDirty("edr-settings", dirty || busy);
  useEffect(() => {
    if (!dirty) {
      const next = makeDraft();
      setDraft(next);
      setBaseline(JSON.stringify(next));
    }
  }, [setting?.updated_at]);
  const save = async (event) => {
    event.preventDefault();
    setBusy(true);
    setMessage(null);
    try {
      await apiRequest("/edr/settings/", {
        method: "PUT",
        body: JSON.stringify({
          ...draft,
          agent_offline_timeout_minutes: Number(
            draft.agent_offline_timeout_minutes,
          ),
        }),
      });
      setBaseline(JSON.stringify(draft));
      await onReload();
      setMessage({ tone: "ok", text: "Настройките на EDR са запазени." });
    } catch (error) {
      setMessage({ tone: "danger", text: error.message });
    } finally {
      setBusy(false);
    }
  };
  return (
    <Panel
      title="Настройки на EDR"
      description="Конфигурация на източника и определяне на свързаността на агентите."
    >
      <form className="settings-form" onSubmit={save}>
        <Notice message={message} />
        <div className="settings-section">
          <div className="settings-section-title">
            <Server size={20} />
            <div>
              <h3>Мениджър и агенти</h3>
              <p>
                Доставчик: Wazuh. Адресът се съхранява като конфигурация на
                интеграцията.
              </p>
            </div>
          </div>
          <div className="settings-fields">
            <Field
              label="Адрес на мениджъра"
              hint="HTTP(S) адрес на вашия Wazuh мениджър."
            >
              <input
                type="url"
                required
                value={draft.manager_url}
                onChange={(event) =>
                  setDraft({ ...draft, manager_url: event.target.value })
                }
                placeholder="https://wazuh.example.com:55000"
              />
            </Field>
            <Field
              label="Праг за офлайн агент, минути"
              hint="Агент без нови данни след този интервал се показва като офлайн."
            >
              <input
                type="number"
                required
                min={1}
                max={10080}
                value={draft.agent_offline_timeout_minutes}
                onChange={(event) =>
                  setDraft({
                    ...draft,
                    agent_offline_timeout_minutes: event.target.value,
                  })
                }
              />
            </Field>
          </div>
        </div>
        <div className="settings-section">
          <div>
            <h3>Обновяване и съхранение</h3>
            <p>Периодът за обновяване на екрана се избира от горната лента.</p>
          </div>
          <p>
            Получените събития се съхраняват на сървъра. Автоматично почистване
            на историята и дистанционно внедряване на агенти не са конфигурирани
            в тази интеграция.
          </p>
        </div>
        <div className="settings-footer">
          <span>
            {dirty
              ? "Има незапазени промени"
              : "Последна промяна: " + formatDate(setting?.updated_at)}
          </span>
          <div>
            <button
              type="button"
              className="secondary"
              disabled={!dirty || busy}
              onClick={() => setDraft(JSON.parse(baseline))}
            >
              Отмени промените
            </button>
            <button className="primary" disabled={!dirty || busy || !setting}>
              {busy ? (
                <Loader2 className="spin" size={15} />
              ) : (
                <Save size={15} />
              )}
              Запази
            </button>
          </div>
        </div>
      </form>
    </Panel>
  );
}

function IntegrationMetrics({ metrics, onRefresh }) {
  return (
    <div className="console-stack">
      <Panel
        title="CrowdSec"
        description="Метрики, получени от свързания източник."
        actions={
          <button className="secondary" onClick={onRefresh}>
            Обнови метриките
          </button>
        }
      >
        <div className="console-stack">
          <Notice
            message={
              !metrics
                ? { tone: "warn", text: "Източникът не е зареден." }
                : !metrics.ok
                  ? {
                      tone: "warn",
                      text:
                        metrics.error || "Източникът на метрики не е достъпен.",
                    }
                  : {
                      tone: "ok",
                      text:
                        "Метрики получени на " +
                        formatDate(metrics.generated_at),
                    }
            }
          />
          {metrics?.ok && !metrics.sections?.length && (
            <p className="subtle">
              В момента източникът не връща таблични метрики.
            </p>
          )}
        </div>
      </Panel>
      {metrics?.sections?.map((section) => (
        <Panel key={section.title} title={section.title}>
          <DataTable
            rows={(section.rows || []).map((row, index) => ({
              ...row,
              id: index,
            }))}
            columns={section.columns.map((key) => ({ key, label: key }))}
            exportName={
              "crowdsec-" + section.title.replace(/[^a-zA-Z0-9]/g, "-")
            }
          />
        </Panel>
      ))}
    </div>
  );
}
