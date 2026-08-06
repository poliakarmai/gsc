/** @type {import('next').NextConfig} */
const nextConfig = {
  env: {
    NEXT_PUBLIC_GSC_API_URL: process.env.GSC_API_URL || '',
  },
};

module.exports = nextConfig;