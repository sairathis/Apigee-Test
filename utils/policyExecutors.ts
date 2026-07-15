import vm from "vm";
import fetch from "node-fetch";
import prisma from "./prisma";
import { jsonToXml, xmlToJson } from "./transform";
import { checkSpikeArrest, checkQuota, cacheGet, cacheSet, issueToken, verifyIssuedToken } from "./runtimeState";

export interface TraceMessage {
  headers: Record<string, string>;
  body: any;
  status?: number;
  reasonPhrase?: string;
}

export interface TraceContext {
  variables: Record<string, any>;
  request: TraceMessage & { method: string; path: string; query: Record<string, string> };
  response: TraceMessage;
  clientIp: string;
  simulateFault?: string;
}

export interface PolicyStepResult {
  status: "success" | "error" | "skipped";
  message: string;
  variablesSet?: Record<string, any>;
  faultResponse?: { status: number; reasonPhrase: string; body: any };
  detail?: any;
}

function b64decode(s: string): string {
  try {
    return Buffer.from(s, "base64").toString("utf-8");
  } catch {
    return "";
  }
}

function resolveJsonPath(obj: any, path: string): any {
  const parts = path.replace(/^\$\.?/, "").split(".").filter(Boolean);
  let cur = obj;
  for (const p of parts) {
    if (cur === undefined || cur === null) return undefined;
    cur = cur[p];
  }
  return cur;
}

type Executor = (policyName: string, config: Record<string, any>, ctx: TraceContext) => Promise<PolicyStepResult>;

const executors: Record<string, Executor> = {
  VerifyAPIKey: async (name, config, ctx) => {
    const key =
      config.apiKeyLocation === "header"
        ? ctx.request.headers[config.apiKeyParam?.toLowerCase()] || ctx.request.headers[config.apiKeyParam]
        : ctx.request.query[config.apiKeyParam];
    if (!key) {
      return { status: "error", message: "API key not found in request", faultResponse: { status: 401, reasonPhrase: "Unauthorized", body: { fault: { faultstring: "Failed to resolve API Key variable request." + config.apiKeyParam, detail: { errorcode: "steps.oauth.v2.FailedToResolveAPIKey" } } } } };
    }
    const app = await prisma.developerApp.findUnique({ where: { consumerKey: key }, include: { developer: true, products: { include: { product: true } } } });
    if (!app || app.status !== "approved") {
      return { status: "error", message: `Invalid API key: ${key}`, faultResponse: { status: 401, reasonPhrase: "Unauthorized", body: { fault: { faultstring: "Invalid API Key", detail: { errorcode: "oauth.v2.InvalidApiKey" } } } } };
    }
    return {
      status: "success",
      message: `API key verified for app "${app.name}"`,
      variablesSet: {
        "verifyapikey.client_id": app.consumerKey,
        "verifyapikey.developer.app.name": app.name,
        "verifyapikey.developer.email": app.developer?.email,
        "verifyapikey.apiproduct.names": app.products.map((p: any) => p.product.name).join(","),
      },
    };
  },
  OAuthV2: async (name, config, ctx) => {
    const authz = ctx.request.headers["authorization"];
    if (config.operation === "GenerateAccessToken") {
      const body = ctx.request.body || {};
      const clientId = body.client_id || ctx.request.headers["client_id"];
      const clientSecret = body.client_secret || ctx.request.headers["client_secret"];
      const grantType = body.grant_type || config.grantType || "client_credentials";
      if (!clientId || !clientSecret) {
        return { status: "error", message: "client_id and client_secret are required in the request body", faultResponse: { status: 400, reasonPhrase: "Bad Request", body: { error: "invalid_request", error_description: "Missing client_id or client_secret" } } };
      }
      const app = await prisma.developerApp.findFirst({ where: { consumerKey: clientId, consumerSecret: clientSecret } });
      if (!app || app.status !== "approved") {
        return { status: "error", message: `Invalid client credentials for client_id ${clientId}`, faultResponse: { status: 401, reasonPhrase: "Unauthorized", body: { error: "invalid_client", error_description: "Client authentication failed" } } };
      }
      const tokenResult = issueToken(clientId, app.id, config.scopes || "", 3600);
      ctx.response.status = 200;
      ctx.response.reasonPhrase = "OK";
      ctx.response.headers["Content-Type"] = "application/json";
      ctx.response.body = { access_token: tokenResult.token, token_type: "Bearer", expires_in: tokenResult.expiresIn, scope: config.scopes || "" };
      ctx.variables["__skipTargetCall"] = true;
      return { status: "success", message: `Access token issued for app "${app.name}" (grant_type=${grantType})`, variablesSet: { "oauthv2.access_token": tokenResult.token, "oauthv2.client_id": clientId, "oauthv2.developer.app.name": app.name } };
    }
    if (config.operation === "VerifyAccessToken") {
      if (!authz || !authz.startsWith("Bearer ")) {
        return { status: "error", message: "Missing bearer token", faultResponse: { status: 401, reasonPhrase: "Unauthorized", body: { fault: { faultstring: "Invalid Access Token", detail: { errorcode: "keymanagement.service.invalid_access_token" } } } } };
      }
      const token = authz.slice(7);
      const result = verifyIssuedToken(token);
      if (!result.valid) {
        return { status: "error", message: result.expired ? "Access token has expired" : "Access token is invalid or was never issued by this simulator", faultResponse: { status: 401, reasonPhrase: "Unauthorized", body: { fault: { faultstring: result.expired ? "Access Token expired" : "Invalid Access Token", detail: { errorcode: result.expired ? "keymanagement.service.access_token_expired" : "keymanagement.service.invalid_access_token" } } } } };
      }
      return { status: "success", message: `Access token verified (client_id ${result.clientId})`, variablesSet: { "oauthv2.client_id": result.clientId, "oauthv2.scope": result.scope } };
    }
    return { status: "success", message: `OAuthV2 ${config.operation} simulated`, variablesSet: { "oauthv2.access_token": "sim_" + Math.random().toString(36).slice(2, 18) } };
  },
  VerifyJWT: async (name, config, ctx) => {
    const authz = ctx.request.headers["authorization"] || "";
    const token = authz.startsWith("Bearer ") ? authz.slice(7) : authz;
    const parts = token.split(".");
    if (parts.length !== 3) {
      return { status: "error", message: "JWT is malformed (expected 3 segments)", faultResponse: { status: 401, reasonPhrase: "Unauthorized", body: { fault: { faultstring: "JWT is not valid", detail: { errorcode: "steps.jwt.InvalidToken" } } } } };
    }
    let payload: any = {};
    try {
      payload = JSON.parse(b64decode(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
    } catch {
      return { status: "error", message: "Unable to decode JWT payload", faultResponse: { status: 401, reasonPhrase: "Unauthorized", body: { fault: { faultstring: "JWT is not valid", detail: { errorcode: "steps.jwt.InvalidToken" } } } } };
    }
    if (payload.exp && Date.now() / 1000 > payload.exp) {
      return { status: "error", message: "JWT has expired", faultResponse: { status: 401, reasonPhrase: "Unauthorized", body: { fault: { faultstring: "JWT has expired", detail: { errorcode: "steps.jwt.TokenExpired" } } } } };
    }
    return { status: "success", message: `JWT verified (issuer check against "${config.issuer}" simulated)`, variablesSet: { "jwt.decoded.claims": payload } };
  },
  BasicAuthentication: async (name, config, ctx) => {
    const authz = ctx.request.headers["authorization"] || "";
    if (config.operation === "Decode") {
      if (!authz.startsWith("Basic ")) {
        return { status: "error", message: "Missing Basic Authorization header", faultResponse: { status: 401, reasonPhrase: "Unauthorized", body: { fault: { faultstring: "Invalid basic authentication header" } } } };
      }
      const decoded = b64decode(authz.slice(6));
      const [user, password] = decoded.split(":");
      return { status: "success", message: "Basic auth decoded", variablesSet: { [config.user]: user, [config.password]: password ? "****" : "" } };
    }
    return { status: "success", message: "Basic auth header encoded" };
  },
  CORS: async (name, config, ctx) => {
    ctx.response.headers["Access-Control-Allow-Origin"] = config.allowOrigins;
    ctx.response.headers["Access-Control-Allow-Methods"] = config.allowMethods;
    ctx.response.headers["Access-Control-Allow-Headers"] = config.allowHeaders;
    if (config.exposeHeaders) ctx.response.headers["Access-Control-Expose-Headers"] = config.exposeHeaders;
    if (config.allowCredentials) ctx.response.headers["Access-Control-Allow-Credentials"] = "true";
    return { status: "success", message: "CORS headers applied to response" };
  },
  AccessControl: async (name, config, ctx) => {
    const ipList: string[] = (config.ipList || "").split(",").map((s: string) => s.trim());
    const matched = ipList.some((ip) => ctx.clientIp === ip.split("/")[0]);
    if (config.action === "DENY" && matched) {
      return { status: "error", message: `Client IP ${ctx.clientIp} is denied by AccessControl`, faultResponse: { status: 403, reasonPhrase: "Forbidden", body: { fault: { faultstring: "Access Denied" } } } };
    }
    if (config.action === "ALLOW" && !matched && ipList.length) {
      return { status: "error", message: `Client IP ${ctx.clientIp} is not in the allow list`, faultResponse: { status: 403, reasonPhrase: "Forbidden", body: { fault: { faultstring: "Access Denied" } } } };
    }
    return { status: "success", message: `Client IP ${ctx.clientIp} passed AccessControl` };
  },
  SpikeArrest: async (name, config, ctx) => {
    const result = checkSpikeArrest(name, config.rate || "100ps");
    if (!result.allowed) {
      return { status: "error", message: `Spike arrest violation (${result.count}/${result.limit} in window)`, faultResponse: { status: 429, reasonPhrase: "Too Many Requests", body: { fault: { faultstring: "Spike arrest violation", detail: { errorcode: "policies.ratelimit.SpikeArrestViolation" } } } } };
    }
    return { status: "success", message: `Within spike arrest rate (${result.count}/${result.limit})` };
  },
  Quota: async (name, config, ctx) => {
    const result = checkQuota(name, Number(config.allowCount) || 1000, Number(config.interval) || 1, config.timeUnit || "hour");
    if (!result.allowed) {
      return { status: "error", message: `Quota exceeded (${result.count}/${result.limit})`, faultResponse: { status: 429, reasonPhrase: "Too Many Requests", body: { fault: { faultstring: "Quota Violation", detail: { errorcode: "policies.ratelimit.QuotaViolation" } } } } };
    }
    return { status: "success", message: `Quota count ${result.count}/${result.limit}`, variablesSet: { "ratelimit.Quota.count": result.count, "ratelimit.Quota.allowed": result.limit } };
  },
  ConcurrentRateLimit: async (name, config, ctx) => {
    return { status: "success", message: `Concurrency simulated within limit of ${config.maxConcurrency}` };
  },
  ResponseCache: async (name, config, ctx) => {
    const key = `rc:${name}:${ctx.request.path}`;
    const cached = cacheGet(key);
    if (cached.hit) {
      ctx.response.body = cached.value;
      ctx.variables["responsecache.cachehit"] = true;
      return { status: "success", message: "Response served from cache (target call will be skipped)", variablesSet: { "responsecache.cachehit": true } };
    }
    ctx.variables["__responseCachePending"] = key;
    ctx.variables["__responseCacheTtl"] = config.ttlSeconds;
    return { status: "success", message: "Cache miss - will populate cache after target call", variablesSet: { "responsecache.cachehit": false } };
  },
  PopulateCache: async (name, config, ctx) => {
    const key = `pc:${config.cacheResource}:${config.cacheKey}:${ctx.request.path}`;
    cacheSet(key, ctx.response.body, Number(config.ttlSeconds) || 300);
    return { status: "success", message: `Wrote response into cache resource "${config.cacheResource}"` };
  },
  LookupCache: async (name, config, ctx) => {
    const key = `pc:${config.cacheResource}:${config.cacheKey}:${ctx.request.path}`;
    const result = cacheGet(key);
    ctx.variables[config.assignTo] = result.hit ? result.value : null;
    return { status: "success", message: result.hit ? "Cache hit" : "Cache miss", variablesSet: { [config.assignTo]: result.hit ? result.value : null } };
  },
  AssignMessage: async (name, config, ctx) => {
    const target = config.assignTo === "response" ? ctx.response : ctx.request;
    const lines: string[] = (config.setHeaders || "").split("\n").filter(Boolean);
    for (const line of lines) {
      const idx = line.indexOf(":");
      if (idx === -1) continue;
      const k = line.slice(0, idx).trim();
      const v = line.slice(idx + 1).trim();
      target.headers[k] = v;
    }
    if (config.setPayload) {
      try {
        target.body = JSON.parse(config.setPayload);
      } catch {
        target.body = config.setPayload;
      }
    }
    return { status: "success", message: `Assigned headers/payload to ${config.assignTo}` };
  },
  ExtractVariables: async (name, config, ctx) => {
    const source = config.source === "response" ? ctx.response.body : ctx.request.body;
    const value = resolveJsonPath(source, config.jsonPath || "$");
    ctx.variables[config.variableName] = value;
    return { status: "success", message: `Extracted "${config.jsonPath}" -> ${config.variableName}`, variablesSet: { [config.variableName]: value } };
  },
  ServiceCallout: async (name, config, ctx) => {
    try {
      const res = await fetch(config.targetUrl, { method: config.method || "GET" });
      const body = await res.json().catch(() => ({}));
      ctx.variables[config.responseVariable] = body;
      return { status: "success", message: `ServiceCallout to ${config.targetUrl} returned ${res.status}`, variablesSet: { [config.responseVariable]: body }, detail: { statusCode: res.status } };
    } catch (err: any) {
      return { status: "error", message: `ServiceCallout failed: ${err.message}`, faultResponse: { status: 502, reasonPhrase: "Bad Gateway", body: { fault: { faultstring: "ServiceCallout request failed" } } } };
    }
  },
  FlowCallout: async (name, config, ctx) => {
    return { status: "success", message: `Shared flow "${config.sharedFlowName}" invoked (see nested steps)` };
  },
  JavaScript: async (name, config, ctx) => {
    const setVars: Record<string, any> = {};
    const sandbox = {
      context: {
        setVariable: (k: string, v: any) => {
          setVars[k] = v;
          ctx.variables[k] = v;
        },
        getVariable: (k: string) => ctx.variables[k],
      },
      request: ctx.request,
      response: ctx.response,
      console: { log: () => {} },
    };
    try {
      vm.createContext(sandbox);
      vm.runInContext(config.source || "", sandbox, { timeout: 250 });
      return { status: "success", message: "JavaScript executed", variablesSet: setVars };
    } catch (err: any) {
      return { status: "error", message: `JavaScript error: ${err.message}`, faultResponse: { status: 500, reasonPhrase: "Internal Server Error", body: { fault: { faultstring: "JavaScript runtime error" } } } };
    }
  },
  MessageLogging: async (name, config, ctx) => {
    const rendered = (config.messageTemplate || "").replace("{organization.name}", "apigee-sim-org").replace("{request.uri}", ctx.request.path).replace("{response.status.code}", String(ctx.response.status || ""));
    return { status: "success", message: `Logged to syslog ${config.syslogHost}:${config.syslogPort} -> "${rendered}"` };
  },
  RaiseFault: async (name, config, ctx) => {
    let body: any = config.errorMessage;
    try {
      body = JSON.parse(config.errorMessage);
    } catch {
    }
    return { status: "error", message: `Fault raised: ${config.statusCode} ${config.reasonPhrase}`, faultResponse: { status: Number(config.statusCode) || 400, reasonPhrase: config.reasonPhrase || "Bad Request", body } };
  },
  JSONToXML: async (name, config, ctx) => {
    const target = config.source === "request" ? ctx.request : ctx.response;
    target.body = jsonToXml(target.body, "root");
    target.headers["Content-Type"] = "application/xml";
    return { status: "success", message: `Converted ${config.source} body from JSON to XML` };
  },
  XMLToJSON: async (name, config, ctx) => {
    const target = config.source === "request" ? ctx.request : ctx.response;
    if (typeof target.body === "string") {
      target.body = xmlToJson(target.body);
      target.headers["Content-Type"] = "application/json";
    }
    return { status: "success", message: `Converted ${config.source} body from XML to JSON` };
  },
  XSLTransform: async (name, config, ctx) => {
    return { status: "success", message: `XSL stylesheet "${config.resourceName}" applied to ${config.source} (simulated passthrough)` };
  },
  SalesforceConnector: async (name, config, ctx) => {
    return { status: "success", message: `Salesforce ${config.operation} on ${config.sobject} simulated`, variablesSet: { "connector.salesforce.result": { id: "SF" + Math.random().toString(36).slice(2, 10), success: true } } };
  },
  BigQueryConnector: async (name, config, ctx) => {
    return { status: "success", message: `BigQuery query executed against ${config.projectId} (simulated)`, variablesSet: { "connector.bigquery.rows": [{ id: 1, value: "sample" }, { id: 2, value: "sample2" }] } };
  },
  CloudStorageConnector: async (name, config, ctx) => {
    return { status: "success", message: `Cloud Storage ${config.operation} on gs://${config.bucket}/${config.objectName} simulated` };
  },
  PubSubConnector: async (name, config, ctx) => {
    return { status: "success", message: `Pub/Sub ${config.operation} on topic "${config.topic}" simulated`, variablesSet: { "connector.pubsub.messageId": Math.random().toString(36).slice(2, 12) } };
  },
};

export function getExecutor(type: string): Executor | undefined {
  return executors[type];
}

export function hasExecutor(type: string): boolean {
  return Boolean(executors[type]);
}
