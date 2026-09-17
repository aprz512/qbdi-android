/* eslint-disable react-refresh/only-export-components */
import { createContext, useContext, useMemo, useReducer, useRef, type Dispatch, type ReactNode } from "react";
import { initialState, type AppState } from "./model";
import { reducer, type Action } from "./reducer";

const StateContext = createContext<AppState | null>(null);
const DispatchContext = createContext<Dispatch<Action> | null>(null);

export function AppStateProvider({ children }: { children: ReactNode }) {
  const [state, baseDispatch] = useReducer(reducer, initialState);
  const pending = useRef(new Set<AbortController>());
  const dispatch = useMemo<Dispatch<Action>>(
    () => (action) => {
      if (["openStarted", "closed", "filterChanged", "indexingStarted"].includes(action.type)) {
        for (const controller of pending.current) controller.abort();
        pending.current.clear();
      }
      baseDispatch(action);
    },
    [],
  );
  return (
    <StateContext.Provider value={state}>
      <DispatchContext.Provider value={dispatch}>{children}</DispatchContext.Provider>
    </StateContext.Provider>
  );
}

export function useAppState() {
  const value = useContext(StateContext);
  if (value === null) throw new Error("AppStateProvider is missing");
  return value;
}

export function useAppDispatch() {
  const value = useContext(DispatchContext);
  if (value === null) throw new Error("AppStateProvider is missing");
  return value;
}
