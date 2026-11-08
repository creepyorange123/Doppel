import type { ProgressEvent } from "../shared/protocol";
import { num } from "../lib/format";

/** Full-window "getting ready" while the analyzer starts. */
export function Opening({ progress, onSkip }: { progress: ProgressEvent | null; onSkip?: () => void }) {
  const total = progress?.total ?? 0;
  const done = progress?.done ?? 0;
  const frac = total > 0 ? Math.min(1, done / total) : 0;
  return (
    <div className="opening">
      <div className="opening-box">
        <span className="wordmark">Doppel</span>
        <h1 className="opening-title">{total > 0 ? `Analyzing ${num(total)} new requests` : "Getting ready"}</h1>
        <div className="progress" role="progressbar" aria-valuemin={0} aria-valuemax={total} aria-valuenow={done}>
          <span style={{ transform: `scaleX(${frac})` }} />
        </div>
        <div className="opening-meta">
          <span>{progress?.label ?? "Starting analyzer"}</span>
          {total > 0 && (
            <span>
              {num(done)} / {num(total)}
            </span>
          )}
        </div>
        {onSkip && (
          <button className="btn btn-quiet" onClick={onSkip}>
            Skip
          </button>
        )}
      </div>
    </div>
  );
}
