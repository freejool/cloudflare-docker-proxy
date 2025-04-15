const dockerHub = "https://registry-1.docker.io";

// 使用标准的 Worker 导出语法
export default {
  async fetch(request, env, ctx) {
    // 基本的错误处理
    try {
      // 调用核心处理逻辑，并将 env 对象传递下去
      return await handleRequest(request, env);
    } catch (error) {
      // 记录错误日志（在 Cloudflare Dashboard Logs 中可见）
      console.error("Worker uncaught error:", error);
      // 返回一个通用的服务器错误响应
      return new Response("Internal Server Error", { status: 500 });
    }
  }
};

// 修改 handleRequest 接收 env 参数
async function handleRequest(request, env) {
  // --- 在函数开始时从 env 对象获取环境变量 ---
  const CUSTOM_DOMAIN = env.CUSTOM_DOMAIN;
  const MODE = env.MODE;
  const TARGET_UPSTREAM = env.TARGET_UPSTREAM; // 主要用于 debug 模式

  // --- 增加一个检查，确保必要的环境变量已设置 ---
  if (!CUSTOM_DOMAIN) {
    console.error("FATAL: CUSTOM_DOMAIN environment variable is not defined!");
    return new Response("Configuration error: CUSTOM_DOMAIN not set.", { status: 500 });
  }
  // 可选：如果 MODE 或 TARGET_UPSTREAM 在所有情况下都需要，也添加检查
  // if (!MODE) { ... }

  // --- 将依赖环境变量的 routes 定义移到函数内部 ---
  const routes = {
    // production / default routes
    ["docker." + CUSTOM_DOMAIN]: dockerHub,
    ["quay." + CUSTOM_DOMAIN]: "https://quay.io",
    ["gcr." + CUSTOM_DOMAIN]: "https://gcr.io",
    ["k8s-gcr." + CUSTOM_DOMAIN]: "https://k8s.gcr.io",
    ["k8s." + CUSTOM_DOMAIN]: "https://registry.k8s.io",
    ["ghcr." + CUSTOM_DOMAIN]: "https://ghcr.io",
    ["cloudsmith." + CUSTOM_DOMAIN]: "https://docker.cloudsmith.io",
    ["ecr." + CUSTOM_DOMAIN]: "https://public.ecr.aws",
  };
  // 根据 MODE 动态添加 staging 路由
  if (MODE === 'staging' || MODE === 'debug') { // 假设 debug 也可用 staging 路由
    routes["docker-staging." + CUSTOM_DOMAIN] = dockerHub;
  }


  // --- 将依赖环境变量的辅助函数定义在 handleRequest 内部 ---
  // 这样它们可以访问上面从 env 获取的变量和动态生成的 routes

  function routeByHosts(host) {
    if (host in routes) {
      return routes[host]; // 使用 handleRequest 作用域内的 routes
    }
    // 使用 handleRequest 作用域内的 MODE 和 TARGET_UPSTREAM
    if (MODE == "debug" && TARGET_UPSTREAM) {
      // 仅在 debug 模式且 TARGET_UPSTREAM 有效时使用
      console.log(`DEBUG: Routing unmatched host ${host} to TARGET_UPSTREAM: ${TARGET_UPSTREAM}`);
      return TARGET_UPSTREAM;
    }
    console.warn(`WARN: Host ${host} not found in routes and not in debug mode or TARGET_UPSTREAM not set.`);
    return ""; // 未匹配且非 debug 回退
  }

  function responseUnauthorized(url) {
    const headers = new Headers();
    // 使用 handleRequest 作用域内的 MODE
    if (MODE == "debug") {
      headers.set(
        "Www-Authenticate",
        `Bearer realm="http://${url.host}/v2/auth",service="cloudflare-docker-proxy"`
      );
    } else {
      // 生产或 staging 环境使用 https 和实际 hostname
      headers.set(
        "Www-Authenticate",
        `Bearer realm="https://${url.hostname}/v2/auth",service="cloudflare-docker-proxy"`
      );
    }
    return new Response(JSON.stringify({ message: "UNAUTHORIZED" }), {
      status: 401,
      headers: headers,
    });
  }


  // --- 以下是主要的请求处理逻辑，现在使用内部定义的辅助函数 ---

  const url = new URL(request.url);
  const upstream = routeByHosts(url.hostname); // 调用内部的 routeByHosts

  if (upstream === "") {
    // 返回 404，并显示当前生效的路由（现在在函数内部定义）
    return new Response(
      JSON.stringify({
        message: "Route not found for host: " + url.hostname,
        available_routes: Object.keys(routes), // 显示当前可用的路由 key
      }),
      {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  }

  const isDockerHub = upstream == dockerHub;
  const authorization = request.headers.get("Authorization");

  // Handle /v2/ endpoint - check auth needed
  if (url.pathname == "/v2/") {
    const newUrl = new URL(upstream + "/v2/");
    const headers = new Headers();
    if (authorization) {
      headers.set("Authorization", authorization);
    }
    console.log(`Fetching HEADERS for ${newUrl.toString()}`);
    const resp = await fetch(newUrl.toString(), {
      method: "GET", // 通常 HEAD 请求更快，但 GET 也能工作
      headers: headers,
      redirect: "follow",
    });
    if (resp.status === 401) {
      console.log(`Auth required for ${newUrl.toString()}, returning 401 with Www-Authenticate.`);
      return responseUnauthorized(url); // 调用内部的 responseUnauthorized
    }
    console.log(`Passthrough response for ${newUrl.toString()} (status: ${resp.status})`);
    return resp; // 直接返回上游响应
  }

  // Handle /v2/auth endpoint - fetch token
  if (url.pathname == "/v2/auth") {
    const checkUrl = new URL(upstream + "/v2/"); // Check the base /v2/ first
    console.log(`Checking auth requirement via ${checkUrl.toString()} for token request`);
    const checkResp = await fetch(checkUrl.toString(), { method: "GET", redirect: "follow" });

    if (checkResp.status !== 401) {
      console.log(`No auth needed according to ${checkUrl.toString()} (status: ${checkResp.status}), returning its response.`);
      // 如果上游 /v2/ 没返回 401，说明可能不需要认证，或者认证方式不同
      // 这里直接返回上游 /v2/ 的响应可能不完全正确，但作为一种处理方式
      // 或者返回一个提示信息
      // return new Response("Upstream did not request authentication via /v2/", {status: checkResp.status});
      return checkResp;
    }

    const authenticateStr = checkResp.headers.get("WWW-Authenticate");
    if (!authenticateStr) {
      console.error(`ERROR: Received 401 from ${checkUrl.toString()} but no WWW-Authenticate header.`);
      return new Response("Upstream returned 401 without WWW-Authenticate header", { status: 502 }); // Bad Gateway
    }

    try {
      const wwwAuthenticate = parseAuthenticate(authenticateStr); // 使用外部定义的 parseAuthenticate
      let scope = url.searchParams.get("scope");

      // DockerHub library image scope fix
      if (scope && isDockerHub) {
        let scopeParts = scope.split(":");
        if (scopeParts.length == 3 && !scopeParts[1].includes("/")) {
          scopeParts[1] = "library/" + scopeParts[1];
          scope = scopeParts.join(":");
          console.log(`Adjusted scope for DockerHub library image: ${scope}`);
        }
      }

      console.log(`Fetching token from ${wwwAuthenticate.realm} with service=${wwwAuthenticate.service} and scope=${scope}`);
      // 调用外部定义的 fetchToken，并传递 env
      return await fetchToken(wwwAuthenticate, scope, authorization, env);
    } catch (e) {
      console.error("Error parsing WWW-Authenticate or fetching token:", e);
      return new Response("Failed to process authentication challenge", { status: 500 });
    }
  }

  // Handle DockerHub library image path redirection (e.g., /v2/busybox/... -> /v2/library/busybox/...)
  if (isDockerHub) {
    const pathParts = url.pathname.substring(1).split("/"); // Remove leading '/' before splitting
    // Check if path is like /v2/imagename/manifests/tag or /v2/imagename/blobs/sha256:...
    // And imagename does not contain '/'
    if (pathParts.length >= 3 && pathParts[0] === 'v2' && !pathParts[1].includes('/') && (pathParts[2] === 'manifests' || pathParts[2] === 'blobs')) {
      const originalPath = url.pathname;
      pathParts.splice(1, 0, "library"); // Insert 'library' after 'v2'
      const newPath = "/" + pathParts.join("/");
      const redirectUrl = new URL(url);
      redirectUrl.pathname = newPath;
      console.log(`Redirecting DockerHub library request from ${originalPath} to ${redirectUrl.toString()}`);
      return Response.redirect(redirectUrl.toString(), 301); // Use 301 Permanent Redirect
    }
  }

  // Forward other requests to the upstream
  const forwardUrl = new URL(upstream + url.pathname + url.search); // Include search params
  console.log(`Forwarding request from ${request.url} to ${forwardUrl.toString()}`);
  const forwardReq = new Request(forwardUrl.toString(), {
    method: request.method,
    headers: request.headers,
    body: request.body, // Ensure body is forwarded
    redirect: isDockerHub ? "manual" : "follow", // Manual redirect for DockerHub blobs
  });

  const resp = await fetch(forwardReq);

  // Handle potential 401 from upstream during forwarding
  if (resp.status == 401) {
    console.log(`Received 401 during forward to ${forwardUrl.toString()}, returning 401 with Www-Authenticate.`);
    return responseUnauthorized(url); // 调用内部的 responseUnauthorized
  }

  // Manually handle DockerHub blob redirects (status 307)
  if (isDockerHub && resp.status == 307) {
    const location = resp.headers.get("Location");
    if (location) {
      console.log(`Manually following DockerHub blob redirect (307) to: ${location}`);
      const redirectResp = await fetch(location, {
        method: "GET", // Redirects are typically GET
        headers: request.headers, // Forward original headers if needed? Check DockerHub requirements. Usually not needed for blob fetch.
        redirect: "follow", // Follow further redirects if any
      });
      console.log(`Response status after following redirect: ${redirectResp.status}`);
      return redirectResp;
    } else {
      console.error(`ERROR: Received 307 from DockerHub but no Location header found.`);
      return new Response("Invalid redirect response from upstream", { status: 502 });
    }
  }

  // Return the response from the upstream
  console.log(`Returning response from upstream ${forwardUrl.toString()} with status ${resp.status}`);
  return resp;
}


// --- Helper functions that DO NOT directly depend on env can remain outside ---

function parseAuthenticate(authenticateStr) {
  // sample: Bearer realm="https://auth.ipv6.docker.com/token",service="registry.docker.io"
  // match strings after =" and before "
  const re = /(?<=\=")(?:\\.|[^"\\])*(?=")/g;
  const matches = authenticateStr.match(re);
  if (matches == null || matches.length < 2) {
    throw new Error(`Invalid Www-Authenticate Header: ${authenticateStr}`);
  }
  return {
    realm: matches[0],
    service: matches[1],
  };
}

// Modified fetchToken to accept env, though not currently using it
async function fetchToken(wwwAuthenticate, scope, authorization, env) {
  const url = new URL(wwwAuthenticate.realm);
  if (wwwAuthenticate.service && wwwAuthenticate.service.length) {
    url.searchParams.set("service", wwwAuthenticate.service);
  }
  if (scope) {
    url.searchParams.set("scope", scope);
  }
  const headers = new Headers();
  // Forward Authorization header if present (for user credentials)
  if (authorization) {
    headers.set("Authorization", authorization);
  }
  // Add User-Agent? Some registries might require it.
  // headers.set('User-Agent', 'Cloudflare-Docker-Proxy/1.0');

  console.log(`Fetching token: GET ${url.toString()}`);
  return await fetch(url.toString(), { method: "GET", headers: headers });
}