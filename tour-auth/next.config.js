/** @type {import('next').NextConfig} */
const nextConfig = {
  experimental: { typedRoutes: true },
  images: { domains: ["res.cloudinary.com"] },
}
module.exports = nextConfig
