import { useEffect, useRef, useState } from "react";
import { groupFingerprint, pinState, type PinState } from "./crypto/pins";

// Fingerprint renders a value as 4-character mono groups that wrap only
// between groups, for reading aloud.
export function Fingerprint({ value, label = "SHA-256 fingerprint" }: { value: string; label?: string }) {
  return (
    <figure className="fingerprint">
      <figcaption>{label}</figcaption>
      <p>
        {groupFingerprint(value).map((group, index) => (
          <span key={index}>{group}</span>
        ))}
      </p>
    </figure>
  );
}

type Props = {
  viewerId: string;
  userId: string;
  name: string;
  fingerprint: string;
  confirmLabel?: string;
  // The recovery key is verified with the same dialog; it passes its own
  // wording and pin state (which also knows about epochs).
  title?: string;
  prompt?: string;
  pin?: PinState;
  onConfirm: () => Promise<void>;
  onClose: () => void;
};

// VerifyKeyDialog is the one place a key becomes trusted. The person compares
// the fingerprint out of band and proves they looked by typing its last
// group. A key that differs from an earlier pin is shown as a block first.
export function VerifyKeyDialog({ viewerId, userId, name, fingerprint, confirmLabel = "Fingerprints match", title, prompt, pin: pinOverride, onConfirm, onClose }: Props) {
  const dialog = useRef<HTMLDialogElement>(null);
  const pin = pinOverride ?? pinState(viewerId, userId, fingerprint);
  const [acknowledged, setAcknowledged] = useState(pin.state !== "changed");
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const groups = groupFingerprint(fingerprint);
  const last = groups[groups.length - 1] ?? "";
  const first = name.split(/[\s@]/)[0] || name;

  useEffect(() => {
    dialog.current?.showModal();
  }, []);

  return (
    <dialog ref={dialog} className="verify" onClose={onClose} aria-labelledby="verify-title">
      {!acknowledged && pin.state === "changed" ? (
        <div className="stack">
          <h2 id="verify-title" className="alert-text">
            <span className="glyph" aria-hidden="true">
              ▲
            </span>
            {title ? `${title}: changed` : `${first}'s key changed`}
          </h2>
          <p className="prose">
            This key is different from the one you verified on {pin.at}. Someone may have replaced it, or {first} set up a new key. Do not share anything
            until you compare the new fingerprint with {first} directly.
          </p>
          <div className="modal-actions">
            <button type="button" className="btn" onClick={onClose}>
              Cancel
            </button>
            <button type="button" className="btn" onClick={() => setAcknowledged(true)}>
              Re-verify
            </button>
          </div>
        </div>
      ) : (
        <form
          className="stack"
          onSubmit={(event) => {
            event.preventDefault();
            if (typed.trim().toLowerCase() !== last.toLowerCase()) {
              setError("That is not the last group shown above.");
              return;
            }
            setBusy(true);
            setError("");
            onConfirm()
              .then(onClose)
              .catch((err) => setError(err instanceof Error ? err.message : String(err)))
              .finally(() => setBusy(false));
          }}
        >
          <h2 id="verify-title">{title ?? `Verify ${first}'s key`}</h2>
          <p className="prose">{prompt ?? `Ask ${first} to read the fingerprint from their screen, on a call or in person. Every group must match.`}</p>
          <Fingerprint value={fingerprint} />
          <label className="field">
            <span>Type the last group ({last.length} characters)</span>
            <input
              value={typed}
              onChange={(event) => setTyped(event.target.value)}
              autoComplete="off"
              spellCheck={false}
              autoCapitalize="off"
              aria-describedby={error ? "verify-error" : undefined}
              required
            />
          </label>
          {error && (
            <p id="verify-error" className="import-error">
              {error}
            </p>
          )}
          <div className="modal-actions">
            <button type="button" className="btn" onClick={onClose}>
              Cancel
            </button>
            <button className="btn primary" disabled={busy}>
              {busy ? "Working…" : confirmLabel}
            </button>
          </div>
          <p className="status-line">&gt; verification is pinned in this browser</p>
        </form>
      )}
    </dialog>
  );
}

// PinBadge shows a member's verification state in lists.
export function PinBadge({ viewerId, userId, fingerprint }: { viewerId: string; userId: string; fingerprint: string }) {
  const pin = pinState(viewerId, userId, fingerprint);
  if (pin.state === "verified") return <span className="ok-text">✓ verified {pin.at}</span>;
  if (pin.state === "changed") return <span className="alert-text">▲ key changed</span>;
  return <span className="warn-text">● not verified</span>;
}
