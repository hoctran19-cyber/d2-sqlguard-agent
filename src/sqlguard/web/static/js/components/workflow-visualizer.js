import { h, spinner } from "../dom.js";
import {
  createPlayback,
  eventNode,
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
    updateAnswer(update) {
      answerState = { ...answerState, ...update, events };
      renderSummary();
      renderRunDetails();
      renderCanvas();
    },
  };

  function renderDynamic() {
    renderSummary();
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
      "A DB schema/syntax failure may trigger at most one repair; all other failures follow controller policy.");
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
    eventDetail.replaceChildren(
      h("h4", {}, "Selected event"),
      metadata,
      detailLevel === "detailed" && event.data
        ? h("pre", { class: "workflow-safe-output" }, JSON.stringify(event.data, null, 2))
        : null,
    );
    renderTimeline();
  }

  function renderRunDetails() {
    if (detailLevel !== "detailed") {
      runDetails.replaceChildren();
      return;
    }
    const details = [
      h("h3", {}, "Run details returned by Query API"),
      h("p", {}, h("strong", {}, "Input: "), answerState.question || "Not provided"),
      h("p", {}, h("strong", {}, "Planner: "),
        answerState.planner === "ollama" ? "Ollama Planner" : answerState.planner || "Not provided"),
      answerState.sql
        ? h("div", {},
          h("h4", {}, "SQL observed from the live planner / Query API"),
          h("pre", { class: "workflow-safe-output" }, answerState.sql))
        : h("p", { class: "muted" }, "SQL has not been observed yet."),
      answerState.result !== undefined && answerState.result !== null
        ? h("div", {},
          h("h4", {}, "Query result returned by the Query API"),
          h("pre", { class: "workflow-safe-output" }, JSON.stringify(answerState.result, null, 2)))
        : h("p", { class: "muted" }, "No query result was returned yet."),
      answerState.reason
        ? h("p", {}, h("strong", {}, "Final message: "), answerState.reason)
        : null,
    ];
    runDetails.replaceChildren(...details);
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
