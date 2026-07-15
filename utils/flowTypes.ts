// Shape of the JSON blobs stored in ProxyRevision.proxyEndpoint / targetEndpoint
// and SharedFlowRevision.steps. Kept framework-agnostic so the same shapes
// can be mirrored on the frontend for the React Flow visual editor.

export interface FlowStepList {
  request: string[]; // ordered ProxyPolicy names
  response: string[];
}

export interface ConditionalFlow {
  name: string;
  condition: { basePathSuffix?: string; verb?: string; description?: string };
  request: string[];
  response: string[];
}

export interface RouteRule {
  name: string;
  targetEndpoint: string;
  condition?: string;
}

export interface ProxyEndpointDef {
  name: string;
  basePath: string;
  preFlow: FlowStepList;
  postFlow: FlowStepList;
  conditionalFlows: ConditionalFlow[];
  routeRules: RouteRule[];
}

export interface TargetEndpointDef {
  name: string;
  preFlow: FlowStepList;
  postFlow: FlowStepList;
  targetServerName?: string;
  url?: string;
  failoverTargetServerName?: string;
  loadBalancingAlgorithm?: "RoundRobin" | "Weighted" | "None";
}

export function defaultProxyEndpoint(basePath: string): ProxyEndpointDef {
  return {
    name: "default",
    basePath,
    preFlow: { request: [], response: [] },
    postFlow: { request: [], response: [] },
    conditionalFlows: [],
    routeRules: [{ name: "default", targetEndpoint: "default" }],
  };
}

export function defaultTargetEndpoint(url: string): TargetEndpointDef {
  return {
    name: "default",
    preFlow: { request: [], response: [] },
    postFlow: { request: [], response: [] },
    url,
  };
}
