# Buzz Domain Language

- **Agent**: Buzz identity plus behavioral configuration.
- **Runner**: a paired, single-owner remote execution host.
- **Deployment**: the binding between one agent and one runner.
- **Runtime**: an allowlisted ACP harness implementation.
- **Desired state**: owner-authored lifecycle intent: `running`, `stopped`, or
  `deleted`.
- **Actual state**: runner-reported container or process state.

“Remote agent” is useful conversational shorthand, but implementation names
should distinguish the agent, runner, and deployment.
