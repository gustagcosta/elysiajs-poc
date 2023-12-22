import { Elysia, t } from 'elysia';
import { prisma } from './prisma';
import { comparePassword, hashPassword, md5hash } from './bcrypt';
import { isAuthenticated } from './auth';
import { cors } from '@elysiajs/cors';
import { swagger } from '@elysiajs/swagger';
import { cookie } from '@elysiajs/cookie';
import { jwt } from '@elysiajs/jwt';

const app = new Elysia()
  .use(cors())
  .use(swagger())
  .get('/', () => 'Hello Elysia')
  .group('/api', (app) =>
    app
      .use(
        jwt({
          name: 'jwt',
          secret: Bun.env.JWT_SECRET!
        })
      )
      .use(cookie())
      .post(
        '/signup',
        async ({ body, set }) => {
          const { email, name, password, username } = body;

          const emailExists = await prisma.user.findUnique({
            where: {
              email
            },
            select: {
              id: true
            }
          });

          if (emailExists) {
            set.status = 400;
            return {
              success: false,
              data: null,
              message: 'Email address already in use.'
            };
          }

          const usernameExists = await prisma.user.findUnique({
            where: {
              username
            },
            select: {
              id: true
            }
          });

          if (usernameExists) {
            set.status = 400;
            return {
              success: false,
              data: null,
              message: 'Someone already taken this username.'
            };
          }

          const { passwordCripted, salt } = await hashPassword(password);

          const newUser = await prisma.user.create({
            data: {
              name,
              email,
              password: passwordCripted,
              salt,
              username
            }
          });

          return {
            success: true,
            message: 'Account created',
            data: {
              user: newUser
            }
          };
        },
        {
          body: t.Object({
            name: t.String(),
            email: t.String(),
            username: t.String(),
            password: t.String()
          })
        }
      )
      .post(
        '/login',
        async ({ body, set, jwt, setCookie }) => {
          const { username, password } = body;
          const user = await prisma.user.findFirst({
            where: {
              OR: [
                {
                  email: username
                },
                {
                  username
                }
              ]
            },
            select: {
              id: true,
              password: true,
              salt: true
            }
          });

          if (!user) {
            set.status = 400;
            return {
              success: false,
              data: null,
              message: 'Invalid credentials'
            };
          }

          const match = await comparePassword(
            password,
            user.salt,
            user.password
          );
          if (!match) {
            set.status = 400;
            return {
              success: false,
              data: null,
              message: 'Invalid credentials'
            };
          }

          const accessToken = await jwt.sign({
            userId: user.id
          });

          const refreshToken = await jwt.sign({
            userId: user.id
          });

          setCookie('access_token', accessToken, {
            maxAge: 15 * 60, // 15 minutes
            path: '/'
          });

          setCookie('refresh_token', refreshToken, {
            maxAge: 86400 * 7, // 7 days
            path: '/'
          });

          return {
            success: true,
            data: null,
            message: 'Account login successfully'
          };
        },
        {
          body: t.Object({
            username: t.String(),
            password: t.String()
          })
        }
      )
      .use(isAuthenticated)
      .get('/me', ({ user }) => {
        return {
          success: true,
          message: 'Fetch authenticated user details',
          data: {
            user
          }
        };
      })
  )
  .listen(3000);

console.log(
  `🦊 Elysia is running at ${app.server?.hostname}:${app.server?.port}`
);
