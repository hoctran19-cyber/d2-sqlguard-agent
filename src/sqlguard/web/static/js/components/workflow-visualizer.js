import { h, spinner } from "../dom.js";
import {
  createPlayback,
  eventNode,
  resolveEvidenceReferences,
  summarizeWorkflow,
  timelineEntries,
  WORKFLOW_NODES,
} from "../workflow.js";

const STATUS_LABELS = {
  pending: "Pending",
  running: "Running",
  retrying: "Retrying",
  success: "Success",
  rejected: "Rejected",
  failed: "Failed",
  skipped: "Skipped",
};

const EVENT_LABELS = {
  run_started: "Run started",
  schema_context_ready: "Planner schema context",
  context_retrieval_started: "Context retrieval started",
  context_retrieval_completed: "Context retrieval completed",
  llm_call_started: "Planner call started",
  llm_call_completed: "Planner call completed",
  sql_generation_started: "SQL generation started",
  sql_generation_completed: "SQL generation completed",
  plan_created: "Plan created",
  security_check_started: "Security check started",
  security_check_completed: "Security check completed",
  tool_call_started: "Tool call started",
  tool_call_completed: "Tool call completed",
  execute_started: "Database execution started",
  execute_completed: "Database execution completed",
  repair_started: "Repair started",
  repair_completed: "Repair completed",
  observe_started: "Result observation started",
  observe_completed: "Result observation completed",
  output_check_completed: "Output check completed",
  answer_completed: "Answer completed",
  memory_state_persisted: "Final state persistence",
  memory_write_completed: "Memory write",
  retry_started: "Retry started",
  run_completed: "Run completed",
  run_refused: "Run refused",
  run_failed: "Run failed",
  run_timed_out: "Run timed out",
  budget_exhausted: "Execution budget exhausted",
};

const FLOW_NODE_IDS = [
  "prompt",
  "memory_context",
  "planner",
  "gate",
  "tool",
  "database",
  "result",
];

export function createWorkflowVisualizer(
  answer,
  {
    live = false,
    playback: playbackOptions = {},
    autoStart = false,
  } = {},
) {
  const events = Array.isArray(answer.events) ? [...answer.events] : [];
  let answerState = { ...answer };
  let liveMode = live;
  let connectionState = live ? "connecting" : "playback";
  let connectionMessage = live ? "Connecting to live event stream…" : "Playback of collected events";
  let followLive = true;
  let traceAssessment = answer.trace_assessment || null;
  const seenSequences = new Set(events.map((event) => event.stream_sequence).filter(Boolean));
  const root = h("section", { class: "workflow-panel", "aria-label": "Workflow visualizer" });
  let detailLevel = "detailed";
  let selectedIndex = -1;
  let playbackStarted = false;
  let playbackSnapshot = {
    index: -1,
    running: false,
    mode: playbackOptions.mode || "step",
    delay: playbackOptions.delay ?? 800,
  };

  const canvas = h("div", { class: "workflow-canvas" });
  const timeline = h("ol", { class: "workflow-timeline" });
  const eventDetail = h("section", { class: "workflow-event-detail", "aria-live": "polite" });
  const connectionStatus = h("p", { class: "workflow-connection", role: "status" });
  const emptyState = h("p", { class: "muted", role: "status" },
    "Waiting for the first agent event…");
  const modeSelect = h("select", { "aria-label": "Playback mode" },
    h("option", { value: "step" }, "Step-by-step"),
    h("option", { value: "auto" }, "Auto-play"),
    h("option", { value: "fast" }, "Fast mode"),
  );
  modeSelect.value = playbackSnapshot.mode;
  const delayLabel = h("label", { class: "workflow-delay" },
    "Delay ",
    h("input", {
      type: "range",
      min: "0",
      max: "3000",
      step: "100",
      value: String(playbackSnapshot.delay),
      "aria-label": "Auto-play delay in milliseconds",
    }),
    h("span", { class: "workflow-delay-value" }, `${playbackSnapshot.delay} ms`),
  );
  const delayInput = delayLabel.querySelector("input");
  const delayValue = delayLabel.querySelector("span");
  const detailSelect = h("select", { "aria-label": "Information level" },
    h("option", { value: "basic" }, "Basic"),
    h("option", { value: "detailed" }, "Detailed"),
  );
  detailLevel = playbackOptions.detailLevel || detailLevel;
  detailSelect.value = detailLevel;
  const controls = h("div", { class: "workflow-controls" },
    h("label", {}, "Playback ", modeSelect),
    delayLabel,
    h("label", {}, "Information ", detailSelect),
  );
  const playbackButtons = h("div", { class: "workflow-playback-buttons" });
  const summary = h("div", { class: "workflow-run-summary" });
  const assessment = h("section", {
    class: "workflow-assessment",
    "aria-label": "Trace scoring evidence",
  });
  const runDetails = h("section", { class: "workflow-run-details" });

  const playback = createPlayback(
    events,
    (snapshot, event) => {
      playbackSnapshot = snapshot;
      if (event) {
        selectedIndex = snapshot.index;
        followLive = false;
      } else if (snapshot.index < 0) {
        selectedIndex = -1;
        followLive = true;
      }
      renderDynamic();
    },
    {},
    { mode: playbackSnapshot.mode, delay: playbackSnapshot.delay },
  );

  modeSelect.addEventListener("change", () => playback.setMode(modeSelect.value));
  delayInput.addEventListener("input", () => {
    playback.setDelay(Number(delayInput.value));
    delayValue.textContent = `${delayInput.value} ms`;
  });
  detailSelect.addEventListener("change", () => {
    detailLevel = detailSelect.value;
    renderRunDetails();
    renderAssessment();
    renderSelectedEvent();
  });

  root.append(
    h("h2", { class: "workflow-title" }, "Workflow Visualizer"),
    connectionStatus,
    h("p", { class: "muted small" },
      "Live execution updates as events arrive. Playback only controls presentation; it never pauses AgentController."),
    controls,
    playbackButtons,
    summary,
    assessment,
    canvas,
    h("h3", {}, "Execution Timeline"),
    timeline,
    eventDetail,
    emptyState,
    runDetails,
  );

  renderDynamic();
  renderTimeline();
  renderConnection();
  renderEmptyState();
  renderRunDetails();
  return {
    element: root,
    appendLiveEvent(event) {
      const sequence = event.stream_sequence;
      if (sequence && seenSequences.has(sequence)) return;
      if (sequence) seenSequences.add(sequence);
      playback.append(event);
      if (autoStart && !playbackStarted) {
        playbackStarted = true;
        playback.start();
      }
      if (followLive && !autoStart) selectedIndex = events.length - 1;
      renderDynamic();
      renderEmptyState();
    },
    setConnectionState(state, message) {
      connectionState = state;
      connectionMessage = message;
      renderConnection();
      renderEmptyState();
    },
    setTraceAssessment(value) {
      traceAssessment = value && typeof value === "object" ? value : null;
      renderAssessment();
    },
    updateAnswer(update) {
      answerState = { ...answerState, ...update, events };
      renderSummary();
      renderRunDetails();
      renderCanvas();
    },
  };

  function renderDynamic() {
    renderSummary();
    renderAssessment();
    renderCanvas();
    renderPlaybackButtons();
    renderSelectedEvent();
    renderTimeline();
  }

  function renderSummary() {
    const all = summarizeWorkflow(events, answerState);
    summary.replaceChildren(
      h("span", {}, `Planner calls: ${all.counts.plannerCalls}`),
      h("span", {}, `SQL checks: ${all.counts.sqlAttempts}`),
      h("span", {}, `Tool calls: ${all.counts.toolCalls}`),
      h("span", {}, `Final state: ${all.finalStatus || (liveMode ? "running" : "Not provided")}`),
    );
  }

  function renderCanvas() {
    const visibleEvents = playbackSnapshot.index >= 0 || (autoStart && playbackStarted)
      ? events.slice(0, playbackSnapshot.index + 1)
      : events;
    const progress = summarizeWorkflow(visibleEvents, answerState);
    const cards = FLOW_NODE_IDS.map((nodeId, index) => {
      const node = WORKFLOW_NODES.find(({ id }) => id === nodeId);
      return h("div", { class: "workflow-node-wrap" },
        renderNode(node, progress.statuses[nodeId]),
        index < FLOW_NODE_IDS.length - 1
          ? h("span", { class: "workflow-arrow", "aria-hidden": "true" }, "→")
          : null,
      );
    });
    const controller = WORKFLOW_NODES.find(({ id }) => id === "controller");
    const controllerEvents = events
      .map((event, index) => ({ event, index }))
      .filter(({ event }) => event.event_type === "run_started" || isTerminal(event.event_type));
    const controllerFocus = controllerEvents.at(-1)?.index ?? controllerEvents[0]?.index;

    canvas.replaceChildren(
      h("div", { class: "workflow-controller" },
        renderNode(controller, progress.statuses.controller, controllerFocus),
        h("span", {}, "Coordinates the run; this is not a single execution step.")),
      h("div", { class: "workflow-flow" }, cards),
      renderBranch(progress, visibleEvents),
      h("div", { class: "workflow-secondary-nodes" },
        renderNode(WORKFLOW_NODES.find(({ id }) => id === "memory_state"),
          progress.statuses.memory_state),
        renderNode(WORKFLOW_NODES.find(({ id }) => id === "observability"),
          progress.statuses.observability)),
    );
  }

  function renderConnection() {
    connectionStatus.className = `workflow-connection ${connectionState}`;
    connectionStatus.textContent = `${liveMode ? "Live execution" : "Playback"} · ${connectionMessage}`;
  }

  function renderEmptyState() {
    emptyState.hidden = events.length > 0;
    if (!events.length && connectionState === "completed") {
      emptyState.textContent = "The run completed without agent events.";
    } else if (!events.length && connectionState === "error") {
      emptyState.textContent = "Live event connection failed before any events were received.";
    }
  }

  function renderNode(node, status, focusIndex = null) {
    const eventIndex = focusIndex ?? lastEventIndexForNode(node.id);
    return h("button", {
      class: `workflow-node ${status} ${selectedIndex === eventIndex && eventIndex !== null ? "focused" : ""}`,
      type: "button",
      disabled: eventIndex === null || eventIndex === undefined,
      "data-node": node.id,
      onclick: () => {
        if (eventIndex !== null && eventIndex !== undefined) playback.select(eventIndex);
      },
    },
    h("strong", {}, node.label),
    h("span", { class: "workflow-status" }, STATUS_LABELS[status] || STATUS_LABELS.pending));
  }

  function renderBranch(progress, visibleEvents) {
    const denied = visibleEvents.some(
      (event) => event.event_type === "security_check_completed" && event.status === "denied",
    );
    const repairIndex = visibleEvents.findLastIndex((event) => event.event_type === "repair_started");
    if (repairIndex >= 0) {
      const repair = visibleEvents[repairIndex];
      const laterEvents = visibleEvents.slice(repairIndex + 1);
      const rechecked = laterEvents.some((event) => event.event_type === "security_check_started");
      const allowedIndex = laterEvents.findLastIndex(
        (event) => event.event_type === "security_check_completed" && event.status === "allowed",
      );
      const toolAfterAllow = allowedIndex >= 0
        && laterEvents.slice(allowedIndex + 1).some((event) => event.event_type === "tool_call_started");
      const repairCause = ["db_schema_error", "db_syntax_error"].includes(repair.error_category)
        ? `Database ${repair.error_category} observed`
        : denied
          ? "Security Gate rejection observed"
          : "Repair event observed";
      return h("div", { class: "workflow-branch-path" },
        denied
          ? h("span", { class: "workflow-branch rejected" },
            "Rejected SQL did not reach the tool")
          : null,
        h("span", { class: "workflow-branch repair" }, `${repairCause} → Planner repair`),
        h("span", { class: "workflow-branch-arrow", "aria-hidden": "true" },
          rechecked ? "→ Security Gate re-check observed" : "→ Gate re-check not yet observed"),
        rechecked && progress.statuses.gate === "success"
          ? h("span", { class: "workflow-branch" }, "→ Gate allowed execution")
          : null,
        toolAfterAllow
          ? h("span", { class: "workflow-branch" }, "→ Tool call observed")
          : null,
      );
    }
    if (denied) {
      return h("p", { class: "workflow-branch rejected" },
        progress.counts.toolCalls
          ? "Gate rejection observed; later tool calls are represented by their own events."
          : "Security Gate rejection observed → tool execution was not observed.");
    }
    const terminal = visibleEvents.at(-1);
    if (terminal && isTerminal(terminal.event_type) && progress.counts.toolCalls === 0) {
      return h("p", { class: "workflow-branch skipped" },
        "Execution was not observed; the run ended before a tool call.");
    }
    return h("p", { class: "workflow-branch" },
      repairCauseFromEvents(visibleEvents));
  }

  function repairCauseFromEvents(visibleEvents) {
    const databaseFailure = visibleEvents.findLast((event) =>
      ["db_schema_error", "db_syntax_error"].includes(event.error_category));
    if (databaseFailure) {
      return `Database ${databaseFailure.error_category} observed; no repair event is present in this trace.`;
    }
    return visibleEvents.length
      ? "No repair event is present in this trace."
      : "Waiting for repair or retry events.";
  }

  function renderPlaybackButtons() {
    playbackButtons.replaceChildren(
      ...(playbackSnapshot.mode === "step" ? [] : [h("button", {
        class: "btn",
        type: "button",
        onclick: () => playback.start(),
        disabled: !events.length || playbackSnapshot.running,
      }, "Play / Resume")]),
      h("button", {
        class: "btn secondary",
        type: "button",
        onclick: () => playback.step(),
        disabled: !events.length,
      }, "Next step"),
      h("button", {
        class: "btn secondary",
        type: "button",
        onclick: () => playback.pause(),
        disabled: !playbackSnapshot.running,
      }, "Pause"),
      h("button", {
        class: "btn secondary",
        type: "button",
        onclick: () => playback.reset(),
        disabled: !events.length,
      }, "Reset"),
      h("span", { class: "muted small" },
        `Event ${playbackSnapshot.index < 0 ? 0 : playbackSnapshot.index + 1} / ${events.length}`),
    );
  }

  function renderTimeline() {
    timeline.replaceChildren(...timelineEntries(events).map(({ event, index, nodeId }) => {
      return h("li", { class: "workflow-timeline-item" },
        h("button", {
          class: `workflow-event ${selectedIndex === index ? "selected" : ""} ${playbackSnapshot.index === index ? "playing" : ""}`,
          type: "button",
          onclick: () => playback.select(index),
        },
        h("span", { class: "workflow-event-name" },
          EVENT_LABELS[event.event_type] || event.event_type),
        h("span", { class: "muted small" }, formatTimestamp(event.timestamp)),
        h("span", {}, [
          event.status || "—",
          nodeLabel(nodeId),
          event.step,
          event.attempt_id,
          event.retry_count ? `retry ${event.retry_count}` : null,
        ].filter(Boolean).join(" · "))),
      );
    }));
  }

  function renderSelectedEvent() {
    if (selectedIndex < 0 || !events[selectedIndex]) {
      eventDetail.replaceChildren(h("p", { class: "muted", role: "status" },
        events.length ? "Select an event to inspect its metadata." : "No event details available."));
      renderTimeline();
      return;
    }
    const event = events[selectedIndex];
    const metadata = h("dl", { class: "workflow-event-metadata" },
      h("dt", {}, "Event"),
      h("dd", {}, EVENT_LABELS[event.event_type] || event.event_type),
      h("dt", {}, "Node"),
      h("dd", {}, nodeLabel(eventNode(event.event_type))),
      h("dt", {}, "Module / step"),
      h("dd", {}, [event.module, event.step].filter(Boolean).join(" / ") || "—"),
      h("dt", {}, "Timestamp"),
      h("dd", {}, formatTimestamp(event.timestamp)),
      h("dt", {}, "Run ID"),
      h("dd", {}, event.run_id || "Not provided"),
      h("dt", {}, "Status"),
      h("dd", {}, event.status || "—"),
      h("dt", {}, "Duration"),
      h("dd", {}, formatDuration(event.duration_ms)),
      h("dt", {}, "Error category"),
      h("dd", {}, event.error_category || "—"),
      h("dt", {}, "Attempt / retry"),
      h("dd", {}, [
        event.attempt_id,
        event.related_attempt_id ? `related ${event.related_attempt_id}` : null,
        event.retry_count !== null && event.retry_count !== undefined
          ? `retry ${event.retry_count}`
          : null,
      ].filter(Boolean).join(" · ") || "—"),
    );
    const safePayload = {
      input: event.input,
      output: event.output,
      evidence: event.evidence,
      data: event.data,
    };
    const hasPayload = Object.values(safePayload).some(
      (value) => value !== undefined && value !== null,
    );
    eventDetail.replaceChildren(
      h("h4", {}, "Selected event"),
      metadata,
      detailLevel === "detailed" && hasPayload
        ? h("pre", { class: "workflow-safe-output" }, JSON.stringify(safePayload, null, 2))
        : null,
    );
    renderTimeline();
  }

  function renderAssessment() {
    if (!traceAssessment || !traceAssessment.criteria) {
      assessment.replaceChildren(
        h("h3", {}, "Trace scoring evidence"),
        h("p", { class: "muted" },
          "Assessment is unavailable until a captured trace can be verified."),
      );
      return;
    }
    const criteria = Object.entries(traceAssessment.criteria);
    assessment.replaceChildren(
      h("h3", {}, "Trace scoring evidence"),
      h("p", { class: "muted small" },
        `Capture: ${traceAssessment.capture_status || "unknown"} · Schema v${traceAssessment.schema_version || "?"}`),
      h("ul", { class: "workflow-criteria" },
        ...criteria.map(([name, criterion]) => {
          const evidenceIds = Array.isArray(criterion.evidence) ? criterion.evidence : [];
          const evidenceEntries = resolveEvidenceReferences(evidenceIds, events);
          const criterionDetails = [
            criterion.actual_access
              ? h("p", { class: "muted small" },
                `Actual database access: ${criterion.actual_access}.`)
              : null,
            criterion.omission_status
              ? h("p", { class: "muted small" },
                `Field omission: ${criterion.omission_status} · User notice: ${criterion.notice_status || "unknown"}.`)
              : null,
            Array.isArray(criterion.omitted_fields) && criterion.omitted_fields.length
              ? h("p", { class: "muted small" },
                `Omitted fields: ${criterion.omitted_fields.join(", ")}`)
              : null,
            criterion.boundaries && typeof criterion.boundaries === "object"
              ? h("ul", { class: "workflow-criterion-boundaries" },
                ...Object.entries(criterion.boundaries).map(([boundary, status]) =>
                  h("li", {}, `${boundary.replaceAll("_", " ")}: ${status}`)))
              : null,
          ].filter(Boolean);
          return h("li", { class: "workflow-criterion" },
            h("strong", {}, name.replaceAll("_", " ")),
            h("span", { class: `workflow-criterion-status ${criterion.status || "unknown"}` },
              criterion.status || "unknown"),
            detailLevel === "detailed"
              ? h("p", {}, criterion.reason || "No assessment reason provided.")
              : null,
            detailLevel === "detailed" && criterionDetails.length
              ? h("div", { class: "workflow-criterion-details" }, ...criterionDetails)
              : null,
            detailLevel === "detailed"
              ? evidenceIds.length
                ? h("ul", { class: "workflow-evidence-list" },
                  ...evidenceEntries.map(({ reference, event }) =>
                    renderEvidence(event, reference)))
                : h("p", { class: "muted small" }, "No event evidence recorded.")
              : null,
          );
        }),
      ),
    );
  }

  function renderEvidence(event, reference) {
    if (!event) {
      const reason = typeof reference === "string"
        ? "The referenced event was not found in the captured trace."
        : "The scoring reference is not a valid event ID.";
      return h("li", {},
        h("details", { class: "workflow-evidence-item unavailable" },
          h("summary", {}, "Evidence unavailable"),
          h("p", { class: "muted small" }, reason),
          typeof reference === "string"
            ? h("p", { class: "workflow-evidence-reference" },
              h("span", {}, "Reference: "),
              h("code", {}, reference))
            : null,
        ));
    }

    const action = EVENT_LABELS[event.event_type] || event.event_type || "Event";
    const module = [event.module, event.step].filter(Boolean).join(" / ")
      || nodeLabel(eventNode(event.event_type));
    const reason = eventReason(event);
    const safePayload = {
      input: event.input,
      output: event.output,
      evidence: event.evidence,
      data: event.data,
    };
    const hasPayload = Object.values(safePayload).some(
      (value) => value !== undefined && value !== null,
    );
    const sequence = Number.isInteger(event.sequence) ? event.sequence : null;

    return h("li", {},
      h("details", { class: "workflow-evidence-item" },
        h("summary", {},
          h("strong", {}, sequence === null ? "Event" : `Event #${sequence}`),
          h("span", {}, `${action} · ${event.status || "status unavailable"}`),
          h("span", { class: "muted small" }, module),
        ),
        h("dl", { class: "workflow-evidence-metadata" },
          h("dt", {}, "Event type"),
          h("dd", {}, event.event_type || "Not provided"),
          h("dt", {}, "Timestamp"),
          h("dd", {}, formatTimestamp(event.timestamp)),
          h("dt", {}, "Run ID"),
          h("dd", {}, event.run_id || "Not provided"),
          h("dt", {}, "Module / step"),
          h("dd", {}, module),
          h("dt", {}, "Status"),
          h("dd", {}, event.status || "Not provided"),
          h("dt", {}, "Error category"),
          h("dd", {}, event.error_category || "—"),
          h("dt", {}, "Reason"),
          h("dd", {}, reason || "No reason recorded."),
        ),
        detailLevel === "detailed" && hasPayload
          ? h("pre", { class: "workflow-safe-output" }, JSON.stringify(safePayload, null, 2))
          : null,
        h("button", {
          type: "button",
          class: "workflow-evidence-open",
          onclick: () => {
            const index = events.indexOf(event);
            if (index >= 0) playback.select(index);
          },
        }, "Open event in timeline"),
      ));
  }

  function renderRunDetails() {
    if (detailLevel !== "detailed") {
      runDetails.replaceChildren();
      return;
    }
    const details = [
      h("h3", {}, "Run summary"),
      h("p", {}, h("strong", {}, "Planner: "),
        answerState.planner === "ollama" ? "Ollama Planner" : answerState.planner || "Not provided"),
      h("p", {}, h("strong", {}, "Final state: "),
        answerState.execution_status || answerState.status || "Not provided"),
      h("p", { class: "muted small" },
        "SQL and module payloads are shown from redacted trace evidence above; result rows remain in the Query response."),
    ];
    runDetails.replaceChildren(...details);
  }

  function selectEventById(eventId) {
    const index = events.findIndex((event) => event.event_id === eventId);
    if (index >= 0) playback.select(index);
  }

  function lastEventIndexForNode(nodeId) {
    for (let index = events.length - 1; index >= 0; index -= 1) {
      if (eventNode(events[index].event_type) === nodeId) return index;
    }
    return null;
  }
}

function nodeLabel(id) {
  return WORKFLOW_NODES.find((node) => node.id === id)?.label || "Observability";
}

function isTerminal(type) {
  return [
    "run_completed",
    "run_refused",
    "run_failed",
    "run_timed_out",
    "budget_exhausted",
  ].includes(type);
}

function formatTimestamp(value) {
  if (!value) return "Not provided";
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? String(value) : date.toLocaleString();
}

function formatDuration(value) {
  return value === null || value === undefined ? "Not provided" : `${Math.round(value)} ms`;
}

function eventReason(event) {
  const candidates = [
    event.error_category,
    event.evidence?.decision_reason,
    event.evidence?.reason,
    event.output?.reason,
    event.data?.reason,
  ];
  return candidates.find((value) => typeof value === "string" && value.length > 0) || null;
}
