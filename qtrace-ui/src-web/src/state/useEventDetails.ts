import { useCallback, useLayoutEffect, useState } from "react";
import { useQtraceApi } from "../api/ApiContext";
import type { AppError, CallTreeDto, EventDetailDto, EventRowDto, MemoryEvidenceDto, MemoryStateDto, RegisterStateDto } from "../api/generated";
import { normalizeAppError } from "../api/TauriQtraceApi";
import { useAppDispatch, useAppState } from "./AppStateProvider";
import type { RequestGuard, RequestScope } from "./RequestScope";
import { useRequestScope } from "./useRequestScope";

export interface EventSelection {
  workspaceId: string;
  projectionId: string;
  artifactIndex: number;
  generation: number;
  row: EventRowDto;
  request: RequestGuard;
}

const emptyDetails = () => ({
  selection: null as EventSelection | null,
  detail: null as EventDetailDto | null,
  registers: null as RegisterStateDto | null,
  memory: null as MemoryStateDto | null,
  memoryHistory: [] as MemoryEvidenceDto[],
  callTree: null as CallTreeDto | null,
  paneErrors: [] as AppError[],
});
type Details = ReturnType<typeof emptyDetails> & { owner: RequestScope; generation: number };
export interface SelectionContext { workspaceId: string; projectionId: string; generation: number }

export function useEventDetails() {
  const api = useQtraceApi();
  const state = useAppState();
  const dispatch = useAppDispatch();
  const scope = useRequestScope(state.opened?.workspace.id ?? null);
  const [stored, setStored] = useState<Details>(() => ({ owner: scope, generation: state.generation, ...emptyDetails() }));
  const view = stored.owner === scope && stored.generation === state.generation ? stored : emptyDetails();
  useLayoutEffect(() => {
    if (stored.generation !== state.generation) scope.invalidate();
  }, [scope, stored.generation, state.generation]);
  const reset = useCallback(() => {
    scope.invalidate();
    setStored({ owner: scope, generation: state.generation, ...emptyDetails() });
  }, [scope, state.generation]);
  const addError = useCallback((error: unknown) => {
    scope.capture().accept(() => setStored(current => ({
      ...(current.owner === scope ? current : { owner: scope, generation: state.generation, ...emptyDetails() }),
      paneErrors: [...(current.owner === scope ? current.paneErrors : []), normalizeAppError(error)],
    })));
  }, [scope, state.generation]);

  const select = (row: EventRowDto, artifactIndex = state.selectedArtifactIndex, context?: SelectionContext): EventSelection | null => {
    if (context === undefined && (state.opened === null || state.projectionId === null)) return null;
    const { workspaceId, projectionId, generation } = context ?? { workspaceId: state.opened!.workspace.id, projectionId: state.projectionId!, generation: state.generation };
    const request = scope.next();
    const selection = { workspaceId, projectionId, generation, artifactIndex, row, request };
    setStored({ owner: scope, generation, ...emptyDetails(), selection });
    dispatch({ type: "selectionChanged", event: row.key });
    const update = (patch: Partial<Details>) => request.accept(() => setStored(current => ({ ...current, ...patch })));
    const fail = (error: unknown) => request.accept(() => addError(error));
    void api.getEventDetail(workspaceId, artifactIndex, row.source_row).then(value => {
      update({ detail: value });
      if (value.memory_range !== null && request.isCurrent()) {
        const { start, end_exclusive } = value.memory_range;
        void api.getMemoryState(workspaceId, artifactIndex, row.source_row, start, end_exclusive).then(memory => update({ memory }), fail);
        void api.getMemoryHistory(workspaceId, artifactIndex, row.source_row, start, end_exclusive).then(memoryHistory => update({ memoryHistory }), fail);
      }
    }, fail);
    void api.getRegisterState(workspaceId, artifactIndex, row.source_row).then(registers => update({ registers }), fail);
    if (row.key.tid !== null) {
      void api.getCallTree(workspaceId, artifactIndex, row.key.timeline_id, row.key.tid).then(callTree => update({ callTree }), fail);
    }
    return selection;
  };

  return { ...view, selectedRow: view.selection?.row ?? null, select, reset, addError, reserveSelection: () => scope.next() };
}
