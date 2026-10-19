import { useLayoutEffect, useMemo } from "react";
import { RequestScope } from "./RequestScope";

export function useRequestScope(identity: unknown): RequestScope {
  const scope = useMemo(() => { void identity; return new RequestScope(); }, [identity]);
  useLayoutEffect(() => {
    scope.activate();
    return () => scope.dispose();
  }, [scope]);
  return scope;
}
