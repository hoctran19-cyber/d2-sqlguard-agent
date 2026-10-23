import assert from "node:assert/strict";
import test from "node:test";

import {
  createPlayback,
  eventNode,
  summarizeWorkflow,
  timelineEntries,
} from "../../src/sqlguard/web/static/js/workflow.js";

class FakeScheduler {
  nextId = 0;
  callbacks = new Map();
  delays = [];

  setTimeout(callback, delay) {
    const id = ++this.nextId;
    this.callbacks.set(id, callback);
    this.delays.push(delay);
    return id;
  }

  clearTimeout(id) {
    this.callbacks.delete(id);
  }

  runNext() {
    const [id, callback] = this.callbacks.entries().next().value || [];
    if (callback) {
      this.callbacks.delete(id);
      callback();
    }
  }
}

test("timeline preserves persisted order and links every event to its workflow node", () => {
  const events = [
    { event_type: "run_started", timestamp: "2026-01-01T00:00:02Z" },
    { event_type: "context_retrieval_completed", timestamp: "2026-01-01T00:00:01Z" },
    { event_type: "security_check_completed", timestamp: "2026-01-01T00:00:03Z" },
  ];

  assert.deepEqual(timelineEntries(events), [
    { event: events[0], index: 0, nodeId: "prompt" },
    { event: events[1], index: 1, nodeId: "memory_context" },
    { event: events[2], index: 2, nodeId: "gate" },
  ]);
  assert.equal(eventNode("repair_started"), "planner");
  assert.equal(eventNode("tool_call_started"), "tool");
  assert.equal(eventNode("execute_completed"), "database");
});

test("summarizes real controller events and prevents a gate rejection from reaching the tool", () => {
  const rejected = summarizeWorkflow([
    { event_type: "run_started", status: "running" },
    { event_type: "security_check_started", status: "running" },
    { event_type: "security_check_completed", status: "denied" },
    { event_type: "run_refused", status: "refused" },
  ]);

  assert.equal(rejected.statuses.gate, "rejected");
  assert.equal(rejected.statuses.tool, "skipped");
  assert.equal(rejected.statuses.result, "rejected");
  assert.equal(rejected.statuses.observability, "success");
  assert.equal(rejected.counts.toolCalls, 0);
  assert.equal(rejected.gateRejected, true);
});

test("repair remains visible and the repaired SQL is checked by the gate again", () => {
  const events = [
    { event_type: "security_check_completed", status: "denied" },
    { event_type: "repair_started", status: "running" },
    { event_type: "repair_completed", status: "completed" },
    { event_type: "security_check_started", status: "running" },
    { event_type: "security_check_completed", status: "allowed" },
    { event_type: "tool_call_started", status: "running" },
    { event_type: "run_completed", status: "succeeded" },
  ];
  const summary = summarizeWorkflow(events);

  assert.equal(summary.gateRejected, true);
  assert.equal(summary.repaired, true);
  assert.equal(summary.statuses.gate, "success");
  assert.equal(summary.counts.toolCalls, 1);
  assert.deepEqual(
    timelineEntries(events).filter(({ event }) => event.event_type.startsWith("security_check_"))
      .map(({ index }) => index),
    [0, 3, 4],
  );
});

test("planner failures, budget exhaustion, and terminal failures are not inferred as success", () => {
  const plannerFailure = summarizeWorkflow([
    { event_type: "run_started", status: "running" },
    { event_type: "llm_call_started", status: "running" },
    { event_type: "llm_call_completed", status: "failed", error_category: "planner_error" },
    { event_type: "run_failed", status: "failed", error_category: "planner_error" },
  ]);
  assert.equal(plannerFailure.statuses.planner, "failed");
  assert.equal(plannerFailure.statuses.result, "failed");
  assert.equal(plannerFailure.counts.plannerCalls, 1);

  const budget = summarizeWorkflow([
    { event_type: "budget_exhausted", status: "failed", error_category: "sql_attempt_budget_exhausted" },
  ]);
  assert.equal(budget.statuses.controller, "failed");
  assert.equal(budget.statuses.result, "failed");

  const timedOut = summarizeWorkflow([
    { event_type: "run_timed_out", status: "failed", error_category: "run_timeout" },
  ]);
  assert.equal(timedOut.statuses.controller, "failed");
});

test("output checks update the Result node only from emitted events", () => {
  const failed = summarizeWorkflow([
    { event_type: "output_check_completed", status: "failed", error_category: "output_check_error" },
  ]);

  assert.equal(failed.statuses.result, "failed");
});

test("does not infer memory persistence from a missing event", () => {
  const inProgress = summarizeWorkflow([
    { event_type: "run_started", status: "running" },
  ]);
  const unobserved = summarizeWorkflow([
    { event_type: "run_started", status: "running" },
    { event_type: "run_failed", status: "failed", error_category: "event_sink_error" },
  ]);
  const failed = summarizeWorkflow([
    { event_type: "run_started", status: "running" },
    { event_type: "run_failed", status: "failed", error_category: "memory_error" },
  ]);

  assert.equal(inProgress.statuses.observability, "running");
  assert.equal(unobserved.statuses.memory_state, "pending");
  assert.equal(unobserved.statuses.observability, "failed");
  assert.equal(failed.statuses.memory_state, "failed");
});

test("playback supports step, auto delay, pause/resume, fast mode, selection, and reset", () => {
  const events = [{ event_type: "run_started" }, { event_type: "run_completed" }];
  const scheduler = new FakeScheduler();
  const selected = [];
  const playback = createPlayback(
    events,
    (snapshot, event) => {
      if (event) selected.push(snapshot.index);
    },
    scheduler,
  );

  assert.equal(playback.snapshot().delay, 800);
  playback.setDelay(-1);
  assert.equal(playback.snapshot().delay, 0);
  playback.setDelay(5000);
  assert.equal(playback.snapshot().delay, 3000);

  playback.step();
  assert.deepEqual(selected, [0]);
  assert.equal(playback.snapshot().mode, "step");

  playback.setMode("auto");
  playback.setDelay(900);
  playback.start();
  assert.deepEqual(scheduler.delays, [900]);
  scheduler.runNext();
  assert.deepEqual(selected, [0, 1]);
  assert.equal(playback.snapshot().running, false);

  playback.reset();
  playback.setMode("auto");
  playback.start();
  playback.setMode("step");
  assert.equal(playback.snapshot().running, false);
  assert.equal(scheduler.callbacks.size, 0);
  playback.setMode("auto");
  playback.start();
  playback.pause();
  assert.equal(scheduler.callbacks.size, 0);
  playback.resume();
  assert.equal(scheduler.delays.at(-1), 900);
  playback.setMode("fast");
  assert.equal(scheduler.delays.at(-1), 0);
  while (scheduler.callbacks.size) scheduler.runNext();
  assert.equal(playback.snapshot().running, false);

  playback.select(1);
  assert.deepEqual(selected, [0, 1, 0, 1, 1]);
  playback.reset();
  assert.equal(playback.snapshot().index, -1);
});

test("playback starts with selected mode and delay and can follow live events", () => {
  const events = [];
  const scheduler = new FakeScheduler();
  const selected = [];
  const playback = createPlayback(
    events,
    (snapshot, event) => {
      if (event) selected.push(event.event_type);
    },
    scheduler,
    { mode: "auto", delay: 1200 },
  );

  assert.equal(playback.snapshot().mode, "auto");
  assert.equal(playback.snapshot().delay, 1200);
  playback.append({ event_type: "run_started" });
  playback.start();
  playback.append({ event_type: "run_completed" });
  assert.deepEqual(scheduler.delays, [1200]);
  scheduler.runNext();
  assert.deepEqual(selected, ["run_started"]);
  assert.deepEqual(scheduler.delays, [1200, 1200]);
  scheduler.runNext();
  assert.deepEqual(selected, ["run_started", "run_completed"]);
  assert.equal(playback.snapshot().running, false);
});

test("playback can consume events appended by a live run without delaying collection", () => {
  const events = [];
  const shown = [];
  const playback = createPlayback(events, (snapshot, event) => {
    if (event) shown.push(event.event_type);
  });
  const liveEvent = { event_type: "run_started" };

  playback.append(liveEvent);
  assert.equal(events.length, 1);
  assert.equal(playback.snapshot().index, -1);
  playback.step();
  assert.deepEqual(shown, ["run_started"]);

  playback.append({ event_type: "run_completed" });
  playback.step();
  assert.deepEqual(shown, ["run_started", "run_completed"]);
});
