import * as React from "react";
import { Server, Trash2 } from "lucide-react";

import {
  inspectRemoteRunnerPairingUri,
  getRemoteRunnerProtocolVersion,
  listRemoteRunners,
  pairRemoteRunner,
  purgeRemoteRunnerWorkspace,
  revokeRemoteRunner,
} from "@/shared/api/tauri";
import type { RemoteRunner } from "@/shared/api/remoteRunnerTypes";
import { Button } from "@/shared/ui/button";
import { useQuery } from "@tanstack/react-query";
import { SettingsSectionHeader } from "./SettingsSectionHeader";

export function RemoteRunnersSettingsCard({
  ownerPubkey,
}: {
  ownerPubkey?: string;
}) {
  const [runners, setRunners] = React.useState<RemoteRunner[]>([]);
  const [uri, setUri] = React.useState("");
  const [sas, setSas] = React.useState<string | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [busy, setBusy] = React.useState(false);
  const protocol = useQuery({
    queryKey: ["remote-runner-protocol"],
    queryFn: getRemoteRunnerProtocolVersion,
    staleTime: 60_000,
  });

  const refresh = React.useCallback(async () => {
    try {
      setRunners(await listRemoteRunners());
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    }
  }, []);

  React.useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(), 15_000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  async function inspect() {
    setError(null);
    try {
      setSas(await inspectRemoteRunnerPairingUri(uri.trim()));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    }
  }

  async function confirmPair() {
    if (!sas) return;
    setBusy(true);
    setError(null);
    try {
      await pairRemoteRunner(uri.trim(), sas);
      setUri("");
      setSas(null);
      await refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  }

  if (protocol.isPending || protocol.data == null) return null;

  return (
    <section className="space-y-5" data-testid="remote-runners-settings">
      <SettingsSectionHeader
        description="Pair Linux hosts that keep agents running after Desktop closes."
        title="Remote runners"
      />

      <div className="space-y-3 rounded-xl border border-border/70 p-4">
        <p className="text-sm text-muted-foreground">
          Run{" "}
          <code className="rounded bg-muted px-1 py-0.5 text-xs">
            docker compose exec buzz-runner buzz-runner pair
          </code>{" "}
          on the host, then paste its one-time URI.
        </p>
        {ownerPubkey ? (
          <p className="break-all text-xs text-muted-foreground">
            Owner public key to paste into the runner:{" "}
            <span className="font-mono">{ownerPubkey}</span>
          </p>
        ) : null}
        <div className="flex gap-2">
          <input
            aria-label="Runner pairing URI"
            className="h-9 min-w-0 flex-1 rounded-md border border-input bg-background px-3 text-sm"
            onChange={(event) => {
              setUri(event.target.value);
              setSas(null);
            }}
            placeholder="buzz://runner-pair?…"
            value={uri}
          />
          <Button disabled={!uri.trim() || busy} onClick={() => void inspect()}>
            Pair
          </Button>
        </div>
        {sas ? (
          <div className="space-y-3 rounded-lg border border-primary/30 bg-primary/5 p-3">
            <p className="text-sm">
              Confirm that both screens show SAS{" "}
              <span className="font-mono text-base font-semibold">{sas}</span>.
            </p>
            <Button disabled={busy} onClick={() => void confirmPair()}>
              Confirm matching SAS
            </Button>
          </div>
        ) : null}
        {error ? <p className="text-sm text-destructive">{error}</p> : null}
      </div>

      <div className="space-y-2">
        {runners.length === 0 ? (
          <p className="text-sm text-muted-foreground">No runners paired.</p>
        ) : (
          runners.map((runner) => (
            <div
              className="flex items-center gap-3 rounded-xl border border-border/70 p-4"
              key={runner.runnerPubkey}
            >
              <Server className="h-5 w-5 text-muted-foreground" />
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <p className="truncate text-sm font-medium">{runner.name}</p>
                  <span
                    className={
                      runner.online
                        ? "text-xs text-success"
                        : "text-xs text-muted-foreground"
                    }
                  >
                    {runner.online ? "Online" : "Offline"}
                  </span>
                </div>
                <p className="truncate text-xs text-muted-foreground">
                  v{runner.runnerVersion ?? "unknown"} · {runner.agentCount}{" "}
                  agents ·{" "}
                  {runner.runtimes.join(", ") || "no runtimes advertised"}
                </p>
                {runner.retiredWorkspaces.length > 0 ? (
                  <div className="mt-2 space-y-1">
                    {runner.retiredWorkspaces.map((agentPubkey) => (
                      <div
                        className="flex items-center gap-2 text-xs text-muted-foreground"
                        key={agentPubkey}
                      >
                        <span className="truncate font-mono">
                          Retired {agentPubkey}
                        </span>
                        <Button
                          onClick={() =>
                            void purgeRemoteRunnerWorkspace(
                              runner.runnerPubkey,
                              agentPubkey,
                            ).then(refresh)
                          }
                          size="sm"
                          variant="outline"
                        >
                          Purge
                        </Button>
                      </div>
                    ))}
                  </div>
                ) : null}
              </div>
              <Button
                aria-label={`Revoke ${runner.name}`}
                onClick={() =>
                  void revokeRemoteRunner(runner.runnerPubkey).then(refresh)
                }
                size="icon"
                variant="ghost"
              >
                <Trash2 className="h-4 w-4" />
              </Button>
            </div>
          ))
        )}
      </div>
    </section>
  );
}
