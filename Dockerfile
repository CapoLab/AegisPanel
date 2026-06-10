FROM node:24-alpine

WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --ignore-scripts
COPY . .

ENV AEGIS_HOST=0.0.0.0
ENV AEGIS_PORT=8080
EXPOSE 8080

CMD ["npm", "start"]
