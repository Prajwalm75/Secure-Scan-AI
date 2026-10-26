FROM node:22-alpine
WORKDIR /app
COPY pnpm-lock.yaml pnpm-workspace.yaml ./
COPY frontend/package.json ./frontend/package.json
RUN corepack enable && pnpm install --frozen-lockfile
COPY frontend ./frontend
RUN pnpm --dir frontend build
EXPOSE 3000
CMD ["pnpm", "--dir", "frontend", "preview"]
