const API_PATH = "/__inabox_api";
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === API_PATH) {
      if (request.method !== "POST") return new Response("Method Not Allowed",{status:405,headers:{Allow:"POST"}});
      const upstream = await fetch(env.APPS_SCRIPT_EXEC_URL,{
        method:"POST",headers:{"Content-Type":"application/json"},body:request.body,redirect:"follow"
      });
      const headers = new Headers(upstream.headers);
      headers.set("Content-Type","application/json; charset=utf-8");
      headers.set("Cache-Control","no-store");
      return new Response(upstream.body,{status:upstream.status,headers});
    }
    const asset = await env.ASSETS.fetch(request);
    const headers = new Headers(asset.headers);
    headers.set("Cross-Origin-Opener-Policy","same-origin");
    headers.set("Cross-Origin-Embedder-Policy","credentialless");
    headers.set("Origin-Agent-Cluster","?1");
    return new Response(asset.body,{status:asset.status,statusText:asset.statusText,headers});
  }
};
