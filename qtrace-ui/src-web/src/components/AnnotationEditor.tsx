import { useEffect, useState } from "react";
import type { AppError } from "../api/generated";
import { normalizeAppError } from "../api/TauriQtraceApi";
import { useRequestScope } from "../state/useRequestScope";
interface AnnotationEditorProps {
  comment: string;
  highlight?: string;
  onSave(value: string): Promise<void>;
  onDelete(): Promise<void>;
  onSaveHighlight?(value: string): Promise<void>;
  onDeleteHighlight?(): Promise<void>;
}
export function AnnotationEditor({ comment, highlight = "", onSave, onDelete, onSaveHighlight, onDeleteHighlight }: AnnotationEditorProps) {
  const [draft, setDraft] = useState(comment);
  const [committed, setCommitted] = useState(comment);
  const [highlightDraft, setHighlightDraft] = useState(highlight);
  const [committedHighlight, setCommittedHighlight] = useState(highlight);
  const [error, setError] = useState<AppError | null>(null);
  const comments = useRequestScope(comment);
  const highlights = useRequestScope(highlight);
  useEffect(() => { setDraft(comment); setCommitted(comment); }, [comment]);
  useEffect(() => { setHighlightDraft(highlight); setCommittedHighlight(highlight); }, [highlight]);
  const save = async () => { const request = comments.next(); try { await onSave(draft); request.accept(() => { setCommitted(draft); setError(null); }); } catch (value) { request.accept(() => setError(normalizeAppError(value))); } };
  const remove = async () => { const request = comments.next(); try { await onDelete(); request.accept(() => { setDraft(""); setCommitted(""); setError(null); }); } catch (value) { request.accept(() => setError(normalizeAppError(value))); } };
  const saveHighlight = async () => { if (onSaveHighlight === undefined) return; const request = highlights.next(); try { await onSaveHighlight(highlightDraft); request.accept(() => { setCommittedHighlight(highlightDraft); setError(null); }); } catch (value) { request.accept(() => setError(normalizeAppError(value))); } };
  const removeHighlight = async () => { if (onDeleteHighlight === undefined) return; const request = highlights.next(); try { await onDeleteHighlight(); request.accept(() => { setHighlightDraft(""); setCommittedHighlight(""); setError(null); }); } catch (value) { request.accept(() => setError(normalizeAppError(value))); } };
  return <section aria-label="Annotation editor"><h3>Annotation</h3><textarea aria-label="Comment" value={draft} onChange={(event) => setDraft(event.target.value)} /><button onClick={() => void save()}>Save</button><button onClick={() => void remove()}>Delete</button><p>Committed: {committed || "none"}</p>{onSaveHighlight !== undefined && <><input aria-label="Highlight" value={highlightDraft} onChange={(event) => setHighlightDraft(event.target.value)} /><button onClick={() => void saveHighlight()}>Save highlight</button><button onClick={() => void removeHighlight()}>Delete highlight</button><p>Committed highlight: {committedHighlight || "none"}</p></>}{error !== null && <p role="alert">{error.code}: {error.detail}</p>}</section>;
}
