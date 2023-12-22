FROM oven/bun

WORKDIR /app

COPY package.json .
COPY bun.lockb .

RUN bun install --production

COPY prisma prisma

RUN bun prisma migrate dev

COPY src src
COPY tsconfig.json .

ENV NODE_ENV production

CMD ["bun", "src/index.ts"]

EXPOSE 3000
