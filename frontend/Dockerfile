FROM node:22-alpine AS dev
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
EXPOSE 5173

FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM build AS prod
EXPOSE 8050
CMD ["npm", "run", "preview", "--", "--host", "0.0.0.0", "--port", "8050"]
