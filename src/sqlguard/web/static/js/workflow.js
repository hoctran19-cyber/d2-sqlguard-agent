export const WORKFLOW_NODES = [
  { id: "prompt", label: "User Prompt" },
  { id: "memory_context", label: "Memory · Context Retrieval" },
  { id: "planner", label: "Planner" },
  { id: "controller", label: "Agent Controller · Orchestrator" },
  { id: "gate", label: "Security Gate" },
  { id: "tool", label: "Tool Execution" },
  { id: "database", label: "Database" },
  { id: "result", label: "Result / Final State" },
  { id: "memory_state", label: "Memory · State Persistence" },
  { id: "observability", label: "Observability" },
];

export function eventNode(eventType) {
  if (eventType === "run_started") return "prompt";
  if (eventType === "schema_context_ready") return "planner";
  if (eventType.startsWith("context_retrieval_")) return "memory_context";
  if (eventType === "memory_state_persisted" || eventType.startsWith("memory_write_")) {
    return "memory_state";
  }
  if (eventType.startsWith("retry_")) return "controller";
  if (
    eventType.startsWith("llm_call_")
    || eventType.startsWith("sql_generation_")
    || eventType === "plan_created"
    || eventType.startsWith("repair_")
  ) return "planner";
  if (eventType.startsWith("security_check_")) return "gate";
  if (eventType.startsWith("tool_call_")) return "tool";
  if (eventType.startsWith("execute_")) return "database";
  if (
    eventType.startsWith("observe_")
    || eventType.startsWith("output_check_")
    || eventType === "answer_completed"
    || eventType.startsWith("run_")
    || eventType === "budget_exhausted"
  ) return "result";
  return "observability";
}

export function timelineEntries(events) {
  return events.map((event, index) => ({ event, index, nodeId: eventNode(event.event_type) }));
}

export function resolveEvidenceReferences(references, events) {
  const eventsById = new Map(
    events.filter((event) => event && typeof event.event_id === "string")
      .map((event) => [event.event_id, event]),
  );
  return references.map((reference) => ({
    reference,
    event: typeof reference === "string" ? eventsById.get(reference) || null : null,
  }));
}

export function summarizeWorkflow(events, answer = {}) {
  const statuses = Object.fromEntries(WORKFLOW_NODES.map(({ id }) => [id, "pending"]));
  const counts = {
    plannerCalls: 0,
    sqlAttempts: 0,
    toolCalls: 0,
  };
  let gateRejected = false;
  let repaired = false;

  const setFromEvent = (node, event, startedTypes, completedTypes) => {
    if (startedTypes.includes(event.event_type)) statuses[node] = "running";
    if (completedTypes.includes(event.event_type)) statuses[node] = statusFromEvent(event);
  };

  for (const event of events) {
    const type = event.event_type;
    if (type === "run_started") {
      statuses.prompt = "success";
      statuses.controller = "running";
      statuses.observability = "running";
    }
    if (type === "llm_call_started") counts.plannerCalls += 1;
    if (type === "security_check_started") counts.sqlAttempts += 1;
    if (type === "tool_call_started") counts.toolCalls += 1;
    if (type === "repair_started") repaired = true;
    if (type === "security_check_completed" && event.status === "denied") gateRejected = true;

    setFromEvent(
      "memory_context",
      event,
      ["context_retrieval_started"],
      ["context_retrieval_completed"],
    );
    setFromEvent(
      "planner",
      event,
      ["llm_call_started", "sql_generation_started", "repair_started"],
      ["llm_call_completed", "sql_generation_completed", "repair_completed", "plan_created"],
    );
    setFromEvent(
      "gate",
      event,
      ["security_check_started"],
      ["security_check_completed"],
    );
    setFromEvent("tool", event, ["tool_call_started"], ["tool_call_completed"]);
    setFromEvent("database", event, ["execute_started"], ["execute_completed"]);
    setFromEvent(
      "result",
      event,
      ["observe_started"],
      ["observe_completed", "output_check_completed", "answer_completed"],
    );

    if (type === "memory_state_persisted") {
      statuses.memory_state = statusFromEvent(event);
    }
    if (type === "memory_write_completed") {
      statuses.memory_state = statusFromEvent(event);
    }
    if (type === "retry_started") statuses.controller = "retrying";
    if (type === "run_completed") {
      statuses.controller = "success";
      statuses.result = "success";
      statuses.observability = "success";
    } else if (type === "run_refused") {
      statuses.controller = "rejected";
      statuses.result = "rejected";
      statuses.observability = "success";
    } else if (type === "run_failed" || type === "run_timed_out" || type === "budget_exhausted") {
      statuses.controller = "failed";
      statuses.result = "failed";
      statuses.observability = event.error_category === "event_sink_error" ? "failed" : "success";
      if (event.error_category === "memory_error") statuses.memory_state = "failed";
    }
  }

  if (events.length) {
    for (const { id } of WORKFLOW_NODES) {
      if (
        id !== "memory_state"
        && statuses[id] === "pending"
        && terminalEvent(events.at(-1)?.event_type)
      ) {
        statuses[id] = "skipped";
      }
    }
  }

  return {
    statuses,
    counts,
    gateRejected,
    repaired,
    finalStatus: answer.execution_status || answer.status || null,
  };
}

function statusFromEvent(event) {
  if (event.status === "denied" || event.status === "blocked") return "rejected";
  if (event.status === "failed") return "failed";
  if (["completed", "allowed"].includes(event.status)) return "success";
  if (["retrying", "repairing"].includes(event.status)) return "retrying";
  return "running";
}

function terminalEvent(type) {
  return (
    type === "run_completed"
    || type === "run_refused"
    || type === "run_failed"
    || type === "run_timed_out"
    || type === "budget_exhausted"
  );
}

export function createPlayback(events, onChange, scheduler = {}, options = {}) {
  const schedule = scheduler.setTimeout
    ? scheduler.setTimeout.bind(scheduler)
    : globalThis.setTimeout;
  const cancel = scheduler.clearTimeout
    ? scheduler.clearTimeout.bind(scheduler)
    : globalThis.clearTimeout;
  let timer = null;
  let index = -1;
  let running = false;
  let mode = ["step", "auto", "fast"].includes(options.mode) ? options.mode : "step";
  let delay = Number.isFinite(options.delay)
    ? Math.min(3000, Math.max(0, Math.round(options.delay)))
    : 800;

  const snapshot = () => ({ index, running, mode, delay });
  const notify = () => onChange(snapshot());
  const clearTimer = () => {
    if (timer !== null) cancel(timer);
    timer = null;
  };
  const advance = () => {
    if (index + 1 >= events.length) {
      running = false;
      clearTimer();
      notify();
      return;
    }
    index += 1;
    onChange(snapshot(), events[index]);
  };
  const scheduleNext = () => {
    clearTimer();
    if (!running || mode === "step" || index + 1 >= events.length) {
      if (index + 1 >= events.length) running = false;
      notify();
      return;
    }
    timer = schedule(() => {
      timer = null;
      advance();
      scheduleNext();
    }, mode === "fast" ? 0 : delay);
  };

  return {
    snapshot,
    start() {
      running = true;
      scheduleNext();
    },
    step() {
      clearTimer();
      mode = "step";
      running = false;
      advance();
      notify();
    },
    append(event) {
      events.push(event);
      if (running && mode !== "step" && timer === null) scheduleNext();
    },
    pause() {
      running = false;
      clearTimer();
      notify();
    },
    resume() {
      running = true;
      scheduleNext();
    },
    reset() {
      running = false;
      clearTimer();
      index = -1;
      notify();
    },
    select(nextIndex) {
      if (!Number.isInteger(nextIndex) || nextIndex < 0 || nextIndex >= events.length) return;
      clearTimer();
      running = false;
      index = nextIndex;
      onChange(snapshot(), events[index]);
    },
    setMode(nextMode) {
      if (!["step", "auto", "fast"].includes(nextMode)) return;
      mode = nextMode;
      if (mode === "step") {
        running = false;
        clearTimer();
        notify();
      } else if (running) scheduleNext();
      else notify();
    },
    setDelay(nextDelay) {
      if (!Number.isFinite(nextDelay)) return;
      delay = Math.min(3000, Math.max(0, Math.round(nextDelay)));
      if (running && mode === "auto") scheduleNext();
      else notify();
    },
  };
}
