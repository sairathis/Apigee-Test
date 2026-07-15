import fetch from "node-fetch";
import prisma from "./prisma";
import { getExecutor, TraceContext, PolicyStepResult } from "./policyExecutors";
import { ProxyEndpointDef, TargetEndpointDef } from "./flowTypes";
import { cacheSet } from "./runtimeState";

export interface TimelineStep {
  order: number;
  phase: string;
  name: string;
  type: string;
  status: "success" | "error" | "skipped";
  message: string;
  durationMs: number;
}

export interface TraceInput {
  proxyName: string;
  environmentName: string;
  method: string;
  path: string;
  headers: Record<string, string>;
  query: Record<string, string>;
  body: any;
  clientIp?: string;
  simulateFault?: string;
}

export interface TraceResult {
  success: boolean;
  durationMs: number;
  request: any;
  response: any;
  timeline: TimelineStep[];
  variables: Record<string, any>;
}

async function runPolicyList(
  names: string[],
  phase: string,
  policyMap: Map<string, { type: string; config: any; enabled: boolean }>,
  ctx: TraceContext,
  timeline: TimelineStep[],
  faulted: { value: boolean }
) {
  for (const name of names) {
    if (faulted.value) {
      timeline.push({ order: timeline.length + 1, phase, name, type: policyMap.get(name)?.type || "Unknown", status: "skipped", message: "Skipped due to earlier fault", durationMs: 0 });
      continue;
    }
    const policy = policyMap.get(name);
    if (!policy || !policy.enabled) {
      timeline.push({ order: timeline.length + 1, phase, name, type: policy?.type || "Unknown", status: "skipped", message: policy ? "Policy disabled" : "Policy not found", durationMs: 0 });
      continue;
    }
    const start = Date.now();
    const forcedFault = ctx.simulateFault && ctx.simulateFault === name;
    const executor = getExecutor(policy.type);
    let result: PolicyStepResult;
    if (forcedFault) {
      result = { status: "error" as const, message: `Fault manually simulated for policy "${name}"`, faultResponse: { status: 500, reasonPhrase: "Internal Server Error", body: { fault: { faultstring: `Simulated failure for ${name}` } } } };
    } else if (executor) {
      try {
        result = await executor(name, policy.config || {}, ctx);
      } catch (err: any) {
        result = { status: "error" as const, message: `Unexpected error: ${err.message}`, faultResponse: { status: 500, reasonPhrase: "Internal Server Error", body: { fault: { faultstring: err.message } } } };
      }
    } else {
      result = { status: "success" as const, message: `${policy.type} executed (simulated)` };
    }
    const durationMs = Date.now() - start;
    if (result.variablesSet) Object.assign(ctx.variables, result.variablesSet);
    timeline.push({ order: timeline.length + 1, phase, name, type: policy.type, status: result.status, message: result.message, durationMs });
    if (result.status === "error") {
      faulted.value = true;
      if ("faultResponse" in result && result.faultResponse) {
        ctx.response.status = result.faultResponse.status;
        ctx.response.reasonPhrase = result.faultResponse.reasonPhrase;
        ctx.response.body = result.faultResponse.body;
      }
    }
  }
}

async function runSharedFlow(
  sharedFlowName: string,
  phaseLabel: string,
  ctx: TraceContext,
  timeline: TimelineStep[],
  faulted: { value: boolean }
) {
  const sf = await prisma.sharedFlow.findUnique({
    where: { name: sharedFlowName },
    include: { revisions: { orderBy: { revision: "desc" }, take: 1, include: { policies: { orderBy: { order: "asc" } } } } },
  });
  if (!sf || sf.revisions.length === 0) {
    timeline.push({ order: timeline.length + 1, phase: phaseLabel, name: sharedFlowName, type: "SharedFlow", status: "skipped", message: "Shared flow not found or has no revisions", durationMs: 0 });
    return;
  }
  const policyMap = new Map(sf.revisions[0].policies.map((p) => [p.name, { type: p.type, config: JSON.parse(p.config), enabled: true }]));
  const names = sf.revisions[0].policies.map((p) => p.name);
  await runPolicyList(names, `${phaseLabel} → SharedFlow:${sharedFlowName}`, policyMap, ctx, timeline, faulted);
}

export async function runTrace(input: TraceInput): Promise<TraceResult> {
  const start = Date.now();
  const timeline: TimelineStep[] = [];
  const faulted = { value: false };

  const environment = await prisma.environment.findUnique({ where: { name: input.environmentName } });
  const proxy = await prisma.proxy.findUnique({ where: { name: input.proxyName } });
  if (!proxy || !environment) {
    throw Object.assign(new Error(`Proxy "${input.proxyName}" or environment "${input.environmentName}" not found`), { status: 404 });
  }

  const deployment = await prisma.deployment.findFirst({
    where: { proxyId: proxy.id, environmentId: environment.id, status: "deployed" },
    orderBy: { deployedAt: "desc" },
    include: { revision: { include: { policies: true } } },
  });
  if (!deployment) {
    throw Object.assign(new Error(`Proxy "${input.proxyName}" is not deployed to "${input.environmentName}"`), { status: 409 });
  }

  const revision = deployment.revision;
  const proxyEndpoint: ProxyEndpointDef = JSON.parse(revision.proxyEndpoint);
  const targetEndpoint: TargetEndpointDef = JSON.parse(revision.targetEndpoint);
  const policyMap = new Map(revision.policies.map((p) => [p.name, { type: p.type, config: JSON.parse(p.config), enabled: p.enabled }]));

  const ctx: TraceContext = {
    variables: {
      "proxy.name": proxy.name,
      "proxy.basepath": proxy.basePath,
      "environment.name": environment.name,
      "request.verb": input.method,
      "request.path": input.path,
    },
    request: { method: input.method, path: input.path, headers: { ...input.headers }, query: { ...input.query }, body: input.body },
    response: { headers: {}, body: null, status: 200, reasonPhrase: "OK" },
    clientIp: input.clientIp || "203.0.113.1",
    simulateFault: input.simulateFault,
  };

  // Flow hooks: global (proxyId null) OR specific to this proxy, for this environment
  const flowHooks = await prisma.flowHook.findMany({ where: { environmentId: environment.id, OR: [{ proxyId: null }, { proxyId: proxy.id }] }, include: { sharedFlow: true } });
  const hookFor = (point: string) => flowHooks.find((h) => h.hookPoint === point);

  // 1. PreProxyFlowHook
  const preProxyHook = hookFor("PreProxyFlowHook");
  if (preProxyHook?.sharedFlow) await runSharedFlow(preProxyHook.sharedFlow.name, "PreProxyFlowHook", ctx, timeline, faulted);

  // 2. ProxyEndpoint PreFlow (Request)
  await runPolicyList(proxyEndpoint.preFlow.request, "ProxyEndpoint PreFlow (Request)", policyMap, ctx, timeline, faulted);

  // 3. Matching Conditional Flow (Request)
  const matchedFlow = proxyEndpoint.conditionalFlows.find(
    (f) => (!f.condition.verb || f.condition.verb.toUpperCase() === input.method.toUpperCase()) && (!f.condition.basePathSuffix || input.path.includes(f.condition.basePathSuffix))
  );
  if (matchedFlow) {
    await runPolicyList(matchedFlow.request, `Conditional Flow: ${matchedFlow.name} (Request)`, policyMap, ctx, timeline, faulted);
  }

  // 4. PreTargetFlowHook
  const preTargetHook = hookFor("PreTargetFlowHook");
  if (preTargetHook?.sharedFlow) await runSharedFlow(preTargetHook.sharedFlow.name, "PreTargetFlowHook", ctx, timeline, faulted);

  // 5. TargetEndpoint PreFlow (Request)
  await runPolicyList(targetEndpoint.preFlow.request, "TargetEndpoint PreFlow (Request)", policyMap, ctx, timeline, faulted);

  // 6. Target Request (real HTTP call, unless faulted earlier, served from cache, or a
  // policy such as OAuthV2 GenerateAccessToken already produced the full response itself)
  const cachedHit = ctx.variables["responsecache.cachehit"] === true;
  const skipTargetCall = ctx.variables["__skipTargetCall"] === true;
  if (!faulted.value && !cachedHit && !skipTargetCall) {
    const targetStart = Date.now();
    let targetUrl = targetEndpoint.url || "";
    if (targetEndpoint.targetServerName) {
      const ts = await prisma.targetServer.findFirst({ where: { name: targetEndpoint.targetServerName } });
      if (ts?.enabled) targetUrl = ts.host;
    }
    try {
      if (!targetUrl) throw new Error("No target URL configured");
      const res = await fetch(targetUrl, { method: input.method === "GET" || input.method === "DELETE" ? input.method : "GET" });
      const contentType = res.headers.get("content-type") || "";
      const body = contentType.includes("application/json") ? await res.json().catch(() => null) : await res.text();
      ctx.response.status = res.status;
      ctx.response.body = body;
      ctx.response.headers["content-type"] = contentType || "application/json";
      timeline.push({ order: timeline.length + 1, phase: "Target Request", name: targetEndpoint.targetServerName || "TargetServer", type: "HTTP Call", status: "success", message: `${input.method} ${targetUrl} → ${res.status}`, durationMs: Date.now() - targetStart });
      if (ctx.variables["__responseCachePending"]) {
        cacheSet(ctx.variables["__responseCachePending"], body, ctx.variables["__responseCacheTtl"] || 300);
      }
    } catch (err: any) {
      // Target failover simulation
      if (targetEndpoint.failoverTargetServerName) {
        try {
          const fallback = await prisma.targetServer.findFirst({ where: { name: targetEndpoint.failoverTargetServerName } });
          if (fallback) {
            const res2 = await fetch(fallback.host, { method: "GET" });
            const body2 = await res2.json().catch(() => null);
            ctx.response.status = res2.status;
            ctx.response.body = body2;
            timeline.push({ order: timeline.length + 1, phase: "Target Request", name: fallback.name, type: "HTTP Call (Failover)", status: "success", message: `Primary target failed, failed over to ${fallback.name} → ${res2.status}`, durationMs: Date.now() - targetStart });
          } else {
            throw err;
          }
        } catch (err2: any) {
          faulted.value = true;
          ctx.response.status = 502;
          ctx.response.body = { fault: { faultstring: "Target and failover target both unreachable" } };
          timeline.push({ order: timeline.length + 1, phase: "Target Request", name: targetEndpoint.targetServerName || "TargetServer", type: "HTTP Call", status: "error", message: `Target call failed: ${err.message}`, durationMs: Date.now() - targetStart });
        }
      } else {
        faulted.value = true;
        ctx.response.status = 502;
        ctx.response.body = { fault: { faultstring: `Target call failed: ${err.message}` } };
        timeline.push({ order: timeline.length + 1, phase: "Target Request", name: targetEndpoint.targetServerName || "TargetServer", type: "HTTP Call", status: "error", message: `Target call failed: ${err.message}`, durationMs: Date.now() - targetStart });
      }
    }
  } else if (cachedHit) {
    timeline.push({ order: timeline.length + 1, phase: "Target Request", name: "ResponseCache", type: "Cache", status: "skipped", message: "Target call skipped - response served from cache", durationMs: 0 });
  } else if (skipTargetCall) {
    timeline.push({ order: timeline.length + 1, phase: "Target Request", name: "OAuthV2", type: "Policy Response", status: "skipped", message: "Target call skipped - response was produced directly by a policy (e.g. OAuthV2 GenerateAccessToken)", durationMs: 0 });
  }

  // 7. TargetEndpoint PostFlow (Response)
  await runPolicyList(targetEndpoint.postFlow.response, "TargetEndpoint PostFlow (Response)", policyMap, ctx, timeline, faulted);

  // 8. PostTargetFlowHook
  const postTargetHook = hookFor("PostTargetFlowHook");
  if (postTargetHook?.sharedFlow) await runSharedFlow(postTargetHook.sharedFlow.name, "PostTargetFlowHook", ctx, timeline, faulted);

  // 9. Conditional Flow (Response)
  if (matchedFlow) {
    await runPolicyList(matchedFlow.response, `Conditional Flow: ${matchedFlow.name} (Response)`, policyMap, ctx, timeline, faulted);
  }

  // 10. ProxyEndpoint PostFlow (Response) - runs even after a fault (mirrors real Apigee DefaultFaultRule behavior)
  const postFlowFaulted = { value: false };
  await runPolicyList(proxyEndpoint.postFlow.response, "ProxyEndpoint PostFlow (Response)", policyMap, ctx, timeline, postFlowFaulted);

  // 11. PostProxyFlowHook
  const postProxyHook = hookFor("PostProxyFlowHook");
  if (postProxyHook?.sharedFlow) await runSharedFlow(postProxyHook.sharedFlow.name, "PostProxyFlowHook", ctx, timeline, postFlowFaulted);

  const durationMs = Date.now() - start;
  const result: TraceResult = {
    success: !faulted.value,
    durationMs,
    request: ctx.request,
    response: ctx.response,
    timeline,
  
    variables: ctx.variables,
  };

  await prisma.traceSession.create({
    data: {
      proxyId: proxy.id,
      proxyName: proxy.name,
      environmentId: environment.id,
      environmentName: environment.name,
      request: JSON.stringify(ctx.request),
      response: JSON.stringify(ctx.response),
      timeline: JSON.stringify(timeline),
      variables: JSON.stringify(ctx.variables),
      success: !faulted.value,
      durationMs,
    },
  });

  return result;
}
