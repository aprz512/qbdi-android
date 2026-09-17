import { useEffect, useState } from "react";
import type { AppError } from "../api/generated";
import { normalizeAppError } from "../api/TauriQtraceApi";
export function AnnotationEditor({ comment, onSave, onDelete }: { comment: string; onSave(value: string): Promise<void>; onDelete(): Promise<void> }) {
  const [draft, setDraft] = useState(comment);
  const [committed, setCommitted] = useState(comment);
  const [error, setError] = useState<AppError | null>(null);
  useEffect(() => { setDraft(comment); setCommitted(comment); }, [comment]);
  const save = async () => { try { await onSave(draft); setCommitted(draft); setError(null); } catch (value) { setError(normalizeAppError(value)); } };
  const remove = async () => { try { await onDelete(); setDraft(""); setCommitted(""); setError(null); } catch (value) { setError(normalizeAppError(value)); } };
  return <section aria-label="Annotation editor"><h3>Annotation</h3><textarea aria-label="Comment" value={draft} onChange={(event) => setDraft(event.target.value)} /><button onClick={() => void save()}>Save</button><button onClick={() => void remove()}>Delete</button><p>Committed: {committed || "none"}</p>{error !== null && <p role="alert">{error.code}: {error.detail}</p>}</section>;
}
