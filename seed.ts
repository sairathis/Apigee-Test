import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";
import { getPolicyDef } from "../src/utils/policyCatalog";
import { defaultProxyEndpoint, defaultTargetEndpoint, ProxyEndpointDef, TargetEndpointDef } from "../src/utils/flowTypes";
import { generateConsumerKey, generateConsumerSecret } from "../src/utils/apiKey";

const prisma = new PrismaClient();

function addPolicyData(revisionId: string, name: string, type: string, configOverrides: Record<string, any> = {}) {
  const def = getPolicyDef(type)!;
  const config = { ...def.defaultConfig, ...configOverrides };
  return {
    revisionId,
    name,
    type,
    category: def.category,
    config: JSON.stringify(config),
    xml: def.buildXml(name, config),
  };
}

async function main() {
  console.log("Seeding Apigee Simulator database...");

  // ------------------------------------------------------------- USER / AUTH
  const passwordHash = await bcrypt.hash("Apigee123!", 10);
  await prisma.user.upsert({
    where: { email: "admin@apigee-sim.local" },
    update: {},
    create: { email: "admin@apigee-sim.local", passwordHash, name: "Org Admin", role: "orgadmin" },
  });

  // ------------------------------------------------------------- ENVIRONMENTS
  const envDefs = [
    { name: "dev", displayName: "Development", type: "BASE" },
    { name: "test", displayName: "Test", type: "BASE" },
    { name: "prod", displayName: "Production", type: "COMPREHENSIVE" },
  ];
  const envs: Record<string, any> = {};
  for (const e of envDefs) {
    envs[e.name] = await prisma.environment.upsert({ where: { name: e.name }, update: {}, create: e });
    await prisma.virtualHost.upsert({
      where: { id: `${e.name}-default-vhost` },
      update: {},
      create: { id: `${e.name}-default-vhost`, name: "default", environmentId: envs[e.name].id, port: e.name === "prod" ? 443 : 9443, hostAliases: `${e.name}.api.apigee-sim.local`, sslEnabled: true },
    });
  }

  await prisma.environmentGroup.upsert({
    where: { name: "default-group" },
    update: {},
    create: { name: "default-group", hostnames: "api.apigee-sim.local,*.apigee-sim.local", envNames: "test,prod" },
  });

  // ------------------------------------------------------------- TARGET SERVERS
  const targetServerDefs = [
    { name: "CustomerService", host: "https://jsonplaceholder.typicode.com/users" },
    { name: "OrderService", host: "https://jsonplaceholder.typicode.com/posts" },
    { name: "ProductService", host: "https://fakestoreapi.com/products" },
    { name: "MockWeather", host: "https://api.open-meteo.com/v1/forecast?latitude=37.77&longitude=-122.42&current_weather=true" },
  ];
  for (const envName of ["dev", "test", "prod"]) {
    for (const ts of targetServerDefs) {
      await prisma.targetServer.upsert({
        where: { name_environmentId: { name: ts.name, environmentId: envs[envName].id } },
        update: {},
        create: { name: ts.name, host: ts.host, port: 443, useSSL: true, enabled: true, environmentId: envs[envName].id },
      });
    }
  }
  // A deliberately unreachable target + working fallback, to demonstrate Target Failover in Trace.
  await prisma.targetServer.upsert({
    where: { name_environmentId: { name: "LegacyBillingService", environmentId: envs.test.id } },
    update: {},
    create: { name: "LegacyBillingService", host: "https://billing.invalid.nonexistent-host.example/api", port: 443, useSSL: true, enabled: true, environmentId: envs.test.id },
  });

  // ------------------------------------------------------------- SHARED FLOW
  const sharedFlow = await prisma.sharedFlow.upsert({
    where: { name: "Common-Security-Flow" },
    update: {},
    create: { name: "Common-Security-Flow", description: "Reusable logging + access control steps attached as a flow hook across proxies." },
  });
  const sfRevision = await prisma.sharedFlowRevision.upsert({
    where: { sharedFlowId_revision: { sharedFlowId: sharedFlow.id, revision: 1 } },
    update: {},
    create: { sharedFlowId: sharedFlow.id, revision: 1, steps: JSON.stringify(["SF-MessageLogging", "SF-AccessControl"]) },
  });
  const sfPolicyCount = await prisma.sharedFlowPolicy.count({ where: { revisionId: sfRevision.id } });
  if (sfPolicyCount === 0) {
    const p1 = getPolicyDef("MessageLogging")!;
    const p1Config = { ...p1.defaultConfig };
    await prisma.sharedFlowPolicy.create({ data: { revisionId: sfRevision.id, name: "SF-MessageLogging", type: "MessageLogging", category: p1.category, config: JSON.stringify(p1Config), xml: p1.buildXml("SF-MessageLogging", p1Config), order: 1 } });
    const p2 = getPolicyDef("AccessControl")!;
    const p2Config = { ...p2.defaultConfig, action: "DENY", ipList: "198.51.100.0/24" };
    await prisma.sharedFlowPolicy.create({ data: { revisionId: sfRevision.id, name: "SF-AccessControl", type: "AccessControl", category: p2.category, config: JSON.stringify(p2Config), xml: p2.buildXml("SF-AccessControl", p2Config), order: 2 } });
  }

  const existingProdHook = await prisma.flowHook.findFirst({ where: { hookPoint: "PreProxyFlowHook", environmentId: envs.prod.id, proxyId: null } });
  if (!existingProdHook) {
    await prisma.flowHook.create({ data: { hookPoint: "PreProxyFlowHook", environmentId: envs.prod.id, sharedFlowId: sharedFlow.id, proxyId: null, continueOnError: true } });
  }

  // ------------------------------------------------------------- PROXIES
  async function createProxy(opts: {
    name: string;
    basePath: string;
    description: string;
    targetServerName: string;
    policies: Array<{ name: string; type: string; overrides?: Record<string, any>; phase: "preRequest" | "postResponse" }>;
    failoverTargetServerName?: string;
    deployEnvs: string[];
  }) {
    const existing = await prisma.proxy.findUnique({ where: { name: opts.name } });
    if (existing) return existing;

    const proxy = await prisma.proxy.create({ data: { name: opts.name, basePath: opts.basePath, description: opts.description } });

    const proxyEndpoint: ProxyEndpointDef = defaultProxyEndpoint(opts.basePath);
    proxyEndpoint.preFlow.request = opts.policies.filter((p) => p.phase === "preRequest").map((p) => p.name);
    proxyEndpoint.postFlow.response = opts.policies.filter((p) => p.phase === "postResponse").map((p) => p.name);

    const targetEndpoint: TargetEndpointDef = defaultTargetEndpoint("");
    targetEndpoint.targetServerName = opts.targetServerName;
    if (opts.failoverTargetServerName) targetEndpoint.failoverTargetServerName = opts.failoverTargetServerName;

    const revision = await prisma.proxyRevision.create({
      data: { proxyId: proxy.id, revision: 1, proxyEndpoint: JSON.stringify(proxyEndpoint), targetEndpoint: JSON.stringify(targetEndpoint) },
    });

    for (const p of opts.policies) {
      await prisma.proxyPolicy.create({ data: addPolicyData(revision.id, p.name, p.type, p.overrides) });
    }

    for (const envName of opts.deployEnvs) {
      await prisma.deployment.create({ data: { proxyId: proxy.id, revisionId: revision.id, environmentId: envs[envName].id, status: "deployed" } });
    }

    return proxy;
  }

  await createProxy({
    name: "CustomerService-v1",
    basePath: "/customers",
    description: "Exposes customer records from the CustomerService backend, protected by an API key.",
    targetServerName: "CustomerService",
    policies: [
      { name: "VA-VerifyKey", type: "VerifyAPIKey", phase: "preRequest" },
      { name: "SA-Ratelimit", type: "SpikeArrest", phase: "preRequest", overrides: { rate: "50ps" } },
      { name: "AM-AddHeader", type: "AssignMessage", phase: "postResponse", overrides: { assignTo: "response", setHeaders: "X-Powered-By: Apigee-Simulator" } },
    ],
    deployEnvs: ["dev", "test", "prod"],
  });

  // Matches the example flow from the spec: VerifyJWT -> SpikeArrest -> AssignMessage -> Target -> Response
  await createProxy({
    name: "OrderService-v1",
    basePath: "/orders",
    description: "Order management API secured with JWT, rate limited, and quota enforced.",
    targetServerName: "OrderService",
    policies: [
      { name: "VerifyJWT", type: "VerifyJWT", phase: "preRequest" },
      { name: "SpikeArrest", type: "SpikeArrest", phase: "preRequest", overrides: { rate: "100pm" } },
      { name: "Quota-Limit", type: "Quota", phase: "preRequest", overrides: { allowCount: 1000, interval: 1, timeUnit: "hour" } },
      { name: "AssignMessage", type: "AssignMessage", phase: "preRequest", overrides: { assignTo: "request", setHeaders: "X-Client: apigee-simulator" } },
    ],
    deployEnvs: ["dev", "test", "prod"],
  });

  await createProxy({
    name: "ProductCatalog-v1",
    basePath: "/products",
    description: "Product catalog with response caching to reduce backend load.",
    targetServerName: "ProductService",
    policies: [
      { name: "VA-VerifyKey", type: "VerifyAPIKey", phase: "preRequest", overrides: { apiKeyLocation: "header", apiKeyParam: "x-api-key" } },
      { name: "Quota-Limit", type: "Quota", phase: "preRequest", overrides: { allowCount: 5000, interval: 1, timeUnit: "day" } },
      { name: "RC-ProductCache", type: "ResponseCache", phase: "preRequest", overrides: { ttlSeconds: 120 } },
    ],
    deployEnvs: ["test", "prod"],
  });

  await createProxy({
    name: "WeatherProxy-v1",
    basePath: "/weather",
    description: "Public weather lookups via Open-Meteo, open to all origins.",
    targetServerName: "MockWeather",
    policies: [
      { name: "CORS-Allow", type: "CORS", phase: "preRequest" },
      { name: "SpikeArrest", type: "SpikeArrest", phase: "preRequest", overrides: { rate: "20ps" } },
    ],
    deployEnvs: ["dev", "test", "prod"],
  });

  await createProxy({
    name: "FailoverDemo-v1",
    basePath: "/failover-demo",
    description: "Demonstrates Target Server failover: the primary target is unreachable and traffic fails over to ProductService.",
    targetServerName: "LegacyBillingService",
    failoverTargetServerName: "ProductService",
    policies: [{ name: "SpikeArrest", type: "SpikeArrest", phase: "preRequest", overrides: { rate: "50ps" } }],
    deployEnvs: ["test"],
  });

  // Real, working OAuthV2 client_credentials flow: POST client_id/client_secret (a
  // DeveloperApp's real consumerKey/consumerSecret) to /oauth/token to get a token,
  // then call /secure with "Authorization: Bearer <token>" and it is genuinely verified.
  await createProxy({
    name: "OAuthToken-v1",
    basePath: "/oauth/token",
    description: "Issues a real OAuth2 access token for a registered developer app (client_credentials grant). POST { client_id, client_secret } as the request body in Trace.",
    targetServerName: "CustomerService",
    policies: [{ name: "OA-GenerateToken", type: "OAuthV2", phase: "preRequest", overrides: { operation: "GenerateAccessToken", grantType: "client_credentials", scopes: "read" } }],
    deployEnvs: ["dev", "test", "prod"],
  });

  await createProxy({
    name: "OAuthProtected-v1",
    basePath: "/secure",
    description: "A protected resource guarded by OAuthV2 VerifyAccessToken - use a token minted by OAuthToken-v1's /oauth/token.",
    targetServerName: "CustomerService",
    policies: [{ name: "OA-VerifyToken", type: "OAuthV2", phase: "preRequest", overrides: { operation: "VerifyAccessToken" } }],
    deployEnvs: ["dev", "test", "prod"],
  });

  // ------------------------------------------------------------- API PRODUCTS
  const allProxyNames = ["CustomerService-v1", "OrderService-v1", "ProductCatalog-v1", "WeatherProxy-v1"];

  const freeTier = await prisma.apiProduct.upsert({
    where: { name: "Free-Tier" },
    update: {},
    create: {
      name: "Free-Tier",
      displayName: "Free Tier",
      description: "Basic access with a low daily quota, suitable for evaluation.",
      approvalType: "auto",
      quotaLimit: 1000,
      quotaInterval: 1,
      quotaTimeUnit: "day",
      scopes: JSON.stringify(["read"]),
      environments: JSON.stringify(["test"]),
      proxies: JSON.stringify(["CustomerService-v1", "WeatherProxy-v1"]),
      operations: JSON.stringify([{ resource: "/customers", verbs: ["GET"] }]),
    },
  });

  const premiumTier = await prisma.apiProduct.upsert({
    where: { name: "Premium-Tier" },
    update: {},
    create: {
      name: "Premium-Tier",
      displayName: "Premium Tier",
      description: "Full access to all proxies with a high monthly quota and monetization enabled.",
      approvalType: "manual",
      quotaLimit: 100000,
      quotaInterval: 1,
      quotaTimeUnit: "month",
      scopes: JSON.stringify(["read", "write"]),
      environments: JSON.stringify(["test", "prod"]),
      proxies: JSON.stringify(allProxyNames),
      operations: JSON.stringify(allProxyNames.map((p) => ({ resource: "/", verbs: ["GET", "POST", "PUT", "DELETE"] }))),
      monetizationEnabled: true,
      ratePlan: JSON.stringify({ price: 0.002, currency: "USD", billingPeriod: "monthly", unit: "per API call" }),
    },
  });

  // ------------------------------------------------------------- DEVELOPERS + APPS
  const developerDefs = [
    { email: "grace.hopper@example.com", firstName: "Grace", lastName: "Hopper", company: "Acme Corp" },
    { email: "ada.lovelace@example.com", firstName: "Ada", lastName: "Lovelace", company: "Analytical Engines Inc" },
    { email: "alan.turing@example.com", firstName: "Alan", lastName: "Turing", company: "Bletchley Labs" },
  ];
  const developers: any[] = [];
  for (const d of developerDefs) {
    const dev = await prisma.developer.upsert({
      where: { email: d.email },
      update: {},
      create: { ...d, userName: d.email.split("@")[0], status: "active" },
    });
    developers.push(dev);
  }

  const appDefs = [
    { name: "Acme-Mobile-App", developer: developers[0], products: [freeTier] },
    { name: "Analytical-Dashboard", developer: developers[1], products: [premiumTier] },
    { name: "Bletchley-Integration", developer: developers[2], products: [freeTier, premiumTier] },
  ];
  for (const a of appDefs) {
    const existing = await prisma.developerApp.findFirst({ where: { name: a.name, developerId: a.developer.id } });
    if (existing) continue;
    await prisma.developerApp.create({
      data: {
        name: a.name,
        developerId: a.developer.id,
        callbackUrl: "https://example.com/oauth/callback",
        consumerKey: generateConsumerKey(),
        consumerSecret: generateConsumerSecret(),
        products: { create: a.products.map((p) => ({ productId: p.id })) },
      },
    });
  }

  // ------------------------------------------------------------- KVM
  let orgKvm = await prisma.kvm.findFirst({ where: { name: "global-config", scope: "organization", environmentId: null } });
  if (!orgKvm) {
    orgKvm = await prisma.kvm.create({ data: { name: "global-config", scope: "organization", encrypted: false } });
  }
  await prisma.kvmEntry.upsert({ where: { kvmId_key: { kvmId: orgKvm.id, key: "support.email" } }, update: {}, create: { kvmId: orgKvm.id, key: "support.email", value: "support@apigee-sim.local" } });
  await prisma.kvmEntry.upsert({ where: { kvmId_key: { kvmId: orgKvm.id, key: "brand.name" } }, update: {}, create: { kvmId: orgKvm.id, key: "brand.name", value: "Apigee Simulator" } });

  const devKvm = await prisma.kvm.upsert({ where: { name_scope_environmentId: { name: "dev-secrets", scope: "environment", environmentId: envs.dev.id } }, update: {}, create: { name: "dev-secrets", scope: "environment", environmentId: envs.dev.id, encrypted: true } });
  await prisma.kvmEntry.upsert({ where: { kvmId_key: { kvmId: devKvm.id, key: "api.upstream.secret" } }, update: {}, create: { kvmId: devKvm.id, key: "api.upstream.secret", value: "sim_secret_do_not_use_in_prod" } });

  // ------------------------------------------------------------- REFERENCES
  await prisma.reference.upsert({
    where: { name: "jwks-reference" },
    update: {},
    create: {
      name: "jwks-reference",
      refers: "jwks-keystore",
      resourceType: "JWKS",
      jwksJson: JSON.stringify({ keys: [{ kty: "RSA", kid: "sim-key-1", use: "sig", alg: "RS256", n: "sim...", e: "AQAB" }] }),
    },
  });
  await prisma.reference.upsert({ where: { name: "prod-keystore-ref" }, update: {}, create: { name: "prod-keystore-ref", refers: "prod-keystore", resourceType: "KeyStore" } });

  // ------------------------------------------------------------- ANALYTICS (historical mock data, ~30 days)
  const existingEvents = await prisma.analyticsEvent.count();
  if (existingEvents === 0) {
    console.log("Generating 30 days of mock analytics events...");
    const proxiesForAnalytics = [
      { name: "CustomerService-v1", baseLatency: 120, errorPct: 0.02 },
      { name: "OrderService-v1", baseLatency: 180, errorPct: 0.05 },
      { name: "ProductCatalog-v1", baseLatency: 90, errorPct: 0.01 },
      { name: "WeatherProxy-v1", baseLatency: 60, errorPct: 0.03 },
    ];
    const envList = [envs.test, envs.prod];
    const rows: any[] = [];
    const now = Date.now();
    for (let day = 30; day >= 0; day--) {
      for (let hour = 0; hour < 24; hour += 2) {
        for (const p of proxiesForAnalytics) {
          for (const env of envList) {
            const requestsInBucket = 5 + Math.round(Math.random() * 25);
            for (let i = 0; i < requestsInBucket; i++) {
              const ts = new Date(now - day * 86400000 - (23 - hour) * 3600000 - Math.round(Math.random() * 3600000));
              const isError = Math.random() < p.errorPct;
              const statusCode = isError ? [400, 401, 429, 500, 502][Math.floor(Math.random() * 5)] : [200, 200, 200, 201, 204][Math.floor(Math.random() * 5)];
              rows.push({
                proxyName: p.name,
                environmentId: env.id,
                timestamp: ts,
                statusCode,
                latencyMs: Math.max(10, Math.round(p.baseLatency + (Math.random() - 0.5) * p.baseLatency)),
                verb: ["GET", "GET", "GET", "POST", "PUT"][Math.floor(Math.random() * 5)],
                clientIp: `203.0.113.${1 + Math.floor(Math.random() * 250)}`,
                errorFlag: isError,
              });
            }
         }
    }
      }
    }
    await prisma.analyticsEvent.createMany({ data: rows });
  }

  console.log("Seeding complete.");
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
     await prisma.$disconnect();
  });
