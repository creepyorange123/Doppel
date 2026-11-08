import type { RequestRow } from "../shared/protocol";
import { Breakdown, Drawer, TierBadge } from "../components/ui";
import { XIcon } from "../components/icons";
import { when } from "../lib/format";

export function RequestDrawer({
  request,
  company,
  topic,
  sensitive,
  onClose,
  onOpenCompany,
}: {
  request: RequestRow;
  company: string | null;
  topic?: string | null;
  sensitive?: boolean;
  onClose: () => void;
  onOpenCompany?: () => void;
}) {
  return (
    <Drawer label="Request details" onClose={onClose}>
      <header className="drawer-head">
        <TierBadge tier={request.tier} score={request.score} />
        <button className="icon-btn" onClick={onClose} aria-label="Close">
          <XIcon />
        </button>
      </header>
      <p className="drawer-summary">{request.summary}</p>
      <dl className="kv">
        <div>
          <dt>Company</dt>
          <dd>
            {company && onOpenCompany ? (
              <button className="link-strong" onClick={onOpenCompany}>
                {company}
              </button>
            ) : (
              (company ?? "Unknown")
            )}
          </dd>
        </div>
        <div>
          <dt>App</dt>
          <dd>{request.app_name ?? "Unknown app"}</dd>
        </div>
        {request.process_name && (
          <div>
            <dt>Process</dt>
            <dd>{request.process_name}</dd>
          </div>
        )}
        {topic && (
          <div>
            <dt>Topic</dt>
            <dd>
              {topic}
              {sensitive && <span className="sensitive">Sensitive</span>}
            </dd>
          </div>
        )}
        <div>
          <dt>Sent to</dt>
          <dd>
            <span className="mono block">{request.dest_domain}</span>
          </dd>
        </div>
        <div>
          <dt>Time</dt>
          <dd>{when(request.captured_at)}</dd>
        </div>
      </dl>
      <h2 className="h2">Score</h2>
      <Breakdown items={request.breakdown} score={request.score} />
    </Drawer>
  );
}
