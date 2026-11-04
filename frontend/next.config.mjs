const backend = process.env.GOVERNAI_API_URL || "http://localhost:8000";

/** @type {import('next').NextConfig} */
export default {
  // Same-origin API calls: the browser only ever talks to Next.
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${backend}/:path*` }];
  },
};
