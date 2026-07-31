import assert from "node:assert/strict";
import test from "node:test";

import {
  canRestartManagedAgent,
  getManagedAgentPrimaryActionLabel,
  isManagedAgentActive,
  respawnManagedAgentWithRules,
  shouldStartManagedAgentForMention,
  startManagedAgentWithRules,
} from "./managedAgentControlActions.ts";

function agent(overrides = {}) {
  return {
    pubkey: "deadbeef".repeat(8),
    name: "Mesh Agent",
    personaId: null,
    relayUrl: "ws://localhost:3000",
    acpCommand: "buzz-acp",
    agentCommand: "goose",
    agentArgs: [],
    mcpCommand: "",
    turnTimeoutSeconds: 320,
    idleTimeoutSeconds: null,
    maxTurnDurationSeconds: null,
    parallelism: 1,
    systemPrompt: null,
    model: "hf://demo/model.gguf",
    envVars: {},
    status: "stopped",
    pid: null,
    createdAt: new Date(0).toISOString(),
    updatedAt: new Date(0).toISOString(),
    lastStartedAt: null,
    lastStoppedAt: null,
    lastExitCode: null,
    lastError: null,
    logPath: null,
    startOnAppLaunch: false,
    backend: { type: "local" },
    backendAgentId: null,
    respondTo: "owner-only",
    respondToAllowlist: [],
    ...overrides,
  };
}

test("relay-mesh agents delegate start to the backend preflight", async () => {
  const meshAgent = agent({
    envVars: {
      BUZZ_AGENT_PROVIDER: "openai",
      OPENAI_COMPAT_BASE_URL: "http://127.0.0.1:9337/v1/",
    },
  });

  let calledWith = null;
  await startManagedAgentWithRules({
    agent: meshAgent,
    startManagedAgent: async (pubkey) => {
      calledWith = pubkey;
    },
  });
  assert.equal(calledWith, meshAgent.pubkey);

  // Backend preflight failures (e.g. no live serve target) propagate as-is.
  await assert.rejects(
    startManagedAgentWithRules({
      agent: meshAgent,
      startManagedAgent: async () => {
        throw new Error("no live serve target is available for this model");
      },
    }),
    /no live serve target/,
  );
});

test("ordinary local agents still start normally", async () => {
  let calledWith = null;
  await startManagedAgentWithRules({
    agent: agent(),
    startManagedAgent: async (pubkey) => {
      calledWith = pubkey;
    },
  });
  assert.equal(calledWith, "deadbeef".repeat(8));
});

// --- respawnManagedAgentWithRules: stop→clear→start boundary tests -----------

test("test_respawn_stop_success_start_failure_onStopped_still_fires", async () => {
  // Prove: onStopped fires at the stop-success boundary even when start later
  // throws.  This is the key discriminator: on round-1 code the clear only
  // ran after the full respawn, so a failed start left the badge intact.
  const runningAgent = agent({ status: "running" });
  let onStoppedFired = false;

  await assert.rejects(
    respawnManagedAgentWithRules({
      agent: runningAgent,
      stopManagedAgent: async () => {
        /* stop succeeds */
      },
      startManagedAgent: async () => {
        throw new Error("start failed");
      },
      onStopped: () => {
        onStoppedFired = true;
      },
    }),
    /start failed/,
  );

  assert.ok(
    onStoppedFired,
    "onStopped must fire at stop-success boundary even when start subsequently fails",
  );
});

test("test_respawn_stop_failure_onStopped_not_called", async () => {
  // Prove: onStopped does NOT fire when stop itself throws.  Clearing on a
  // failed stop would remove a badge that is still legitimately active.
  const runningAgent = agent({ status: "running" });
  let onStoppedFired = false;

  await assert.rejects(
    respawnManagedAgentWithRules({
      agent: runningAgent,
      stopManagedAgent: async () => {
        throw new Error("stop failed");
      },
      startManagedAgent: async () => {
        /* should not be reached */
      },
      onStopped: () => {
        onStoppedFired = true;
      },
    }),
    /stop failed/,
  );

  assert.ok(
    !onStoppedFired,
    "onStopped must NOT fire when stop itself fails — badge is still active",
  );
});

test("test_respawn_onStopped_fires_before_start_resolves", async () => {
  // Prove: onStopped fires strictly between stop resolution and start
  // invocation.  A clear that fires after start begins can tombstone genuine
  // new turns from the freshly spawned process.
  const runningAgent = agent({ status: "running" });
  const events = [];

  await respawnManagedAgentWithRules({
    agent: runningAgent,
    stopManagedAgent: async () => {
      events.push("stop");
    },
    startManagedAgent: async () => {
      events.push("start");
    },
    onStopped: () => {
      events.push("onStopped");
    },
  });

  assert.deepEqual(
    events,
    ["stop", "onStopped", "start"],
    "onStopped must fire after stop resolves and before start is called",
  );
});

test("runner activity is derived from container state, not legacy deployed status", () => {
  const runner = agent({
    backend: { type: "runner", runner_pubkey: "ab".repeat(32) },
    status: "stopped",
    deploymentState: "running",
  });
  assert.equal(isManagedAgentActive(runner), true);
  assert.equal(getManagedAgentPrimaryActionLabel(runner), "Stop");
  assert.equal(
    getManagedAgentPrimaryActionLabel({
      ...runner,
      deploymentState: "stopped_by_agent",
    }),
    "Start",
  );
  assert.equal(
    getManagedAgentPrimaryActionLabel({
      ...runner,
      deploymentState: "runner_offline",
    }),
    "Start",
  );
});

test("active runner deployments expose the same restart action as local agents", () => {
  const runner = agent({
    backend: { type: "runner", runner_pubkey: "ab".repeat(32) },
    status: "stopped",
    deploymentState: "running",
  });

  assert.equal(canRestartManagedAgent(runner), true);
  assert.equal(
    canRestartManagedAgent({
      ...runner,
      deploymentState: "stopped_by_owner",
    }),
    false,
  );
  assert.equal(
    canRestartManagedAgent({
      ...runner,
      backend: { type: "provider", id: "cloud", config: {} },
      status: "deployed",
      deploymentState: null,
    }),
    false,
  );
});

test("mentioning an active runner deployment does not publish another start generation", () => {
  const runner = agent({
    backend: { type: "runner", runner_pubkey: "ab".repeat(32) },
    status: "stopped",
    deploymentState: "running",
  });

  assert.equal(shouldStartManagedAgentForMention(runner), false);
  assert.equal(
    shouldStartManagedAgentForMention({
      ...runner,
      deploymentState: "stopped_by_owner",
    }),
    true,
  );
});

test("restarting a runner publishes one new desired generation without stopping first", async () => {
  const runner = agent({
    backend: { type: "runner", runner_pubkey: "ab".repeat(32) },
    status: "stopped",
    deploymentState: "running",
  });
  const calls = [];

  await respawnManagedAgentWithRules({
    agent: runner,
    startManagedAgent: async (pubkey) => {
      calls.push(`start:${pubkey}`);
    },
    stopManagedAgent: async (pubkey) => {
      calls.push(`stop:${pubkey}`);
    },
  });

  assert.deepEqual(calls, [`start:${runner.pubkey}`]);
});
