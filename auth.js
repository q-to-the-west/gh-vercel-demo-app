import NextAuth from 'next-auth';
import Credentials from 'next-auth/providers/credentials';
import { authConfig } from './auth.config';
import { z } from 'zod';
import { neon } from '@neondatabase/serverless';
import bcrypt from 'bcrypt';

async function getUser(email) {
  try {
    //console.log("Searching Database from URL...")
    const sql = neon(`${process.env.DATABASE_URL}`);
    //console.log("Database URL found!")
    //console.log(sql)
    //console.log("Locating entry in database...")
    const user = await sql`SELECT * FROM users WHERE email=${email}`;
    //console.log("User located!")
    //console.log(user[0])
    //console.log("Returning...")
    return user[0];
  } catch (error) {
    console.error('Failed to fetch user:', error);
    throw new Error('Failed to fetch user.');
  }
}

export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [Credentials({
      async authorize(credentials) {
        //console.log("Credentials...")
        //console.log(credentials)
        const parsedCredentials = z
          .object({ email: z.string().email(), password: z.string().min(6) })
          .safeParse(credentials);
        //console.log('\n')
        //console.log("Parsed Credentials...")
        //console.log(parsedCredentials)
        //console.log('\n')
        if (parsedCredentials.success) {
          const { email, password } = parsedCredentials.data;
          const user = await getUser(email);

          if (!user) return null;
          
          const passwordsMatch = await bcrypt.compare(password, user.password);
          if (passwordsMatch) return user;
        }
        console.log('Invalid credentials');
        return null;
      },
    }),
  ],
});