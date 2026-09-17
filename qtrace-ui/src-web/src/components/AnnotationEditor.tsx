import { useEffect, useState } from "react";
import type { AppError } from "../api/generated";
import { normalizeAppError } from "../api/TauriQtraceApi";
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
  useEffect(() => { setDraft(comment); setCommitted(comment); }, [comment]);
  useEffect(() => { setHighlightDraft(highlight); setCommittedHighlight(highlight); }, [highlight]);
  const save = async () => { try { await onSave(draft); setCommitted(draft); setError(null); } catch (value) { setError(normalizeAppError(value)); } };
  const remove = async () => { try { await onDelete(); setDraft(""); setCommitted(""); setError(null); } catch (value) { setError(normalizeAppError(value)); } };
  const saveHighlight = async () => { if (onSaveHighlight === undefined) return; try { await onSaveHighlight(highlightDraft); setCommittedHighlight(highlightDraft); setError(null); } catch (value) { setError(normalizeAppError(value)); } };
  const removeHighlight = async () => { if (onDeleteHighlight === undefined) return; try { await onDeleteHighlight(); setHighlightDraft(""); setCommittedHighlight(""); setError(null); } catch (value) { setError(normalizeAppError(value)); } };
  return <section aria-label="Annotation editor"><h3>Annotation</h3><textarea aria-label="Comment" value={draft} onChange={(event) => setDraft(event.target.value)} /><button onClick={() => void save()}>Save</button><button onClick={() => void remove()}>Delete</button><p>Committed: {committed || "none"}</p>{onSaveHighlight !== undefined && <><input aria-label="Highlight" value={highlightDraft} onChange={(event) => setHighlightDraft(event.target.value)} /><button onClick={() => void saveHighlight()}>Save highlight</button><button onClick={() => void removeHighlight()}>Delete highlight</button><p>Committed highlight: {committedHighlight || "none"}</p></>}{error !== null && <p role="alert">{error.code}: {error.detail}</p>}</section>;
}
