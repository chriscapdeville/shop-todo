FROM node:22-slim
WORKDIR /app
COPY server.js ./
COPY public ./public
ENV NODE_ENV=production DATA_DIR=/data PORT=3000
EXPOSE 3000
CMD ["node", "--no-warnings", "server.js"]
