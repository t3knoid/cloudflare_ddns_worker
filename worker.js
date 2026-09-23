export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // 1. Extract query parameters sent by the Omada router
    const ip = url.searchParams.get('ip');
    const domain = url.searchParams.get('domain');
    const secret = url.searchParams.get('secret');

    // 2. Security Check: Compares against the secret token stored in Cloudflare Environment
    if (!secret || secret !== env.OMADA_SECRET_TOKEN) {
      return new Response("Unauthorized", { status: 401 });
    }

    if (!ip || !domain) {
      return new Response("Missing parameters (ip and domain are required)", { status: 400 });
    }

    try {
      // 3. Find the existing DNS record ID for the domain
      const searchUrl = `https://api.cloudflare.com/client/v4/zones/${env.CLOUDFLARE_ZONE_ID}/dns_records?name=${domain}&type=A`;
      const searchResponse = await fetch(searchUrl, {
        headers: {
          "Authorization": `Bearer ${env.CLOUDFLARE_API_TOKEN}`,
          "Content-Type": "application/json"
        }
      });

      const searchData = await searchResponse.json();
      if (!searchData.success || searchData.result.length === 0) {
        return new Response(`DNS Record for ${domain} not found. Please create an 'A' record manually first.`, { status: 404 });
      }

      // Handle the array format from Cloudflare API correctly
      const dnsRecord = searchData.result[0];
      const recordId = dnsRecord.id;
      const currentIp = dnsRecord.content;

      // 4. If the IP hasn't changed, skip updating to save API calls
      if (currentIp === ip) {
        return new Response("IP unchanged", { status: 200 });
      }

      // 5. Update the DNS record with the new IP
      const updateUrl = `https://api.cloudflare.com/client/v4/zones/${env.CLOUDFLARE_ZONE_ID}/dns_records/${recordId}`;
      const updateResponse = await fetch(updateUrl, {
        method: "PUT",
        headers: {
          "Authorization": `Bearer ${env.CLOUDFLARE_API_TOKEN}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          type: "A",
          name: domain,
          content: ip,
          ttl: 1,
          proxied: false
        })
      });

      const updateData = await updateResponse.json();
      if (updateData.success) {
        return new Response("SUCCESS", { status: 200 });
      } else {
        return new Response(`Cloudflare API Error: ${JSON.stringify(updateData.errors)}`, { status: 500 });
      }

    } catch (error) {
      return new Response(`Worker Error: ${error.message}`, { status: 500 });
    }
  }
};
