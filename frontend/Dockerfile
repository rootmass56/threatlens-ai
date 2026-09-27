FROM node:22.23.2-alpine3.24@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS build

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
ARG VITE_THREATLENS_API_URL=""
ENV VITE_THREATLENS_API_URL=${VITE_THREATLENS_API_URL}
RUN npm run typecheck && npm run build

FROM nginx:1.30.4-alpine3.24@sha256:dc5069ad14f19660b141b21236140b91656bf89bbc3e2417c70ae650cd66104c
# THREATLENS_BATCH7F_TARGETED_OS_PATCH_BEGIN
# Generated from exact V2 Trivy fixable Alpine OS-package findings.
RUN apk upgrade --no-cache libuuid libexpat
# THREATLENS_BATCH7F_TARGETED_OS_PATCH_END
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/ || exit 1
