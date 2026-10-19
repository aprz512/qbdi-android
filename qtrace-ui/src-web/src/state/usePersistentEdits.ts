import { useEffect, useState } from "react";
import { useQtraceApi } from "../api/ApiContext";
import type { AnnotationDto } from "../api/generated";
import type { EventSelection } from "./useEventDetails";
import { useRequestScope } from "./useRequestScope";

export function usePersistentEdits(selection: EventSelection | null, onError: (error: unknown) => void) {
  const api = useQtraceApi();
  const commentScope = useRequestScope(selection);
  const highlightScope = useRequestScope(selection);
  const [stored, setStored] = useState<{ selection: EventSelection; value: AnnotationDto } | null>(null);

  useEffect(() => {
    if (selection === null) return;
    const comment = commentScope.capture();
    const highlight = highlightScope.capture();
    void api.getAnnotation(selection.workspaceId, selection.artifactIndex, selection.row.source_row).then(value => {
      if (!selection.request.isCurrent() || (!comment.isCurrent() && !highlight.isCurrent())) return;
      setStored(current => {
        const previous = current?.selection === selection ? current.value : null;
        return { selection, value: {
          key: selection.row.key,
          comment: comment.isCurrent() ? value?.comment ?? "" : previous?.comment ?? "",
          highlight: highlight.isCurrent() ? value?.highlight ?? null : previous?.highlight ?? null,
        } };
      });
    }, error => {
      if (selection.request.isCurrent() && (comment.isCurrent() || highlight.isCurrent())) onError(error);
    });
  }, [api, selection, commentScope, highlightScope, onError]);

  const writeAnnotation = async (kind: "comment" | "highlight", value?: string) => {
    if (selection === null || !selection.request.isCurrent()) return;
    const request = (kind === "comment" ? commentScope : highlightScope).next();
    const { workspaceId, artifactIndex, row } = selection;
    if (kind === "comment") {
      if (value === undefined) await api.deleteAnnotation(workspaceId, artifactIndex, row.source_row);
      else await api.upsertAnnotation(workspaceId, artifactIndex, row.source_row, value);
    } else {
      if (value === undefined) await api.deleteHighlight(workspaceId, artifactIndex, row.source_row);
      else await api.upsertHighlight(workspaceId, artifactIndex, row.source_row, value);
    }
    if (!request.isCurrent() || !selection.request.isCurrent()) return;
    setStored(current => {
      const previous = current?.selection === selection ? current.value : { key: row.key, comment: "", highlight: null };
      return { selection, value: kind === "comment" ? { ...previous, comment: value ?? "" } : { ...previous, highlight: value ?? null } };
    });
  };

  return { annotation: stored?.selection === selection ? stored?.value ?? null : null, writeAnnotation };
}
