const API_PATH = "/__inabox_api";

function jsonResponse(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

async function wait(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Apps Script ContentService responds to POST with a redirect to a temporary
// script.googleusercontent.com URL. Handle that redirect explicitly so the
// POST is sent only once, then retrieve the temporary response as a GET.
async function callAppsScript(request, env) {
  const endpoint = env.APPS_SCRIPT_EXEC_URL;
  if (!endpoint) return jsonResponse({ok:false,error:"The Apps Script URL is not configured in Cloudflare."}, 500);

  let response;
  try {
    response = await fetch(endpoint, {
      method: "POST",
      headers: {"Content-Type":"application/json", "Accept":"application/json"},
      body: request.body,
      redirect: "manual"
    });
  } catch (error) {
    return jsonResponse({ok:false,error:"Cloudflare could not contact Apps Script: " + String(error)}, 502);
  }

  let currentUrl = endpoint;
  for (let hop = 0; hop < 5; hop++) {
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get("Location");
      if (!location) {
        return jsonResponse({ok:false,error:"Apps Script returned HTTP " + response.status + " without a redirect location."}, 502);
      }
      currentUrl = new URL(location, currentUrl).toString();
      try {
        response = await fetch(currentUrl, {
          method: "GET",
          headers: {"Accept":"application/json"},
          redirect: "manual"
        });
      } catch (error) {
        return jsonResponse({ok:false,error:"Could not retrieve the Apps Script response: " + String(error)}, 502);
      }
      // Google has had intermittent 404s while publishing ContentService's
      // one-time response URL. Retry only this GET, never the original POST.
      if (response.status === 404) {
        await wait(900);
        try {
          response = await fetch(currentUrl, {
            method: "GET",
            headers: {"Accept":"application/json"},
            redirect: "manual"
          });
        } catch (error) {
          return jsonResponse({ok:false,error:"Could not retry the Apps Script response: " + String(error)}, 502);
        }
      }
      continue;
    }

    const body = await response.text();
    let data;
    try {
      data = JSON.parse(body);
    } catch (_) {
      const contentType = response.headers.get("Content-Type") || "unknown";
      return jsonResponse({
        ok:false,
        error:"Apps Script returned HTTP " + response.status + " instead of JSON (Content-Type: " + contentType + ").",
        detail: body.slice(0, 500)
      }, 502);
    }
    return jsonResponse(data, response.ok ? 200 : response.status);
  }

  return jsonResponse({ok:false,error:"Apps Script redirected too many times."}, 502);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === API_PATH) {
      if (request.method !== "POST") {
        return new Response("Method Not Allowed", {status:405, headers:{Allow:"POST"}});
      }
      return callAppsScript(request, env);
    }

    const asset = await env.ASSETS.fetch(request);
    const headers = new Headers(asset.headers);
    headers.set("Cross-Origin-Opener-Policy", "same-origin");
    headers.set("Cross-Origin-Embedder-Policy", "credentialless");
    headers.set("Origin-Agent-Cluster", "?1");
    return new Response(asset.body, {
      status:asset.status,
      statusText:asset.statusText,
      headers
    });
  }
};
