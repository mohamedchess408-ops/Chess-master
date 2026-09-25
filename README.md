# Chess Mastery

Deploy-ready Node/Express starter for the Chess Mastery paid chess-course site.

Includes registration/login, admin role, course/chapter structure, PGN chapter splitting, and PayPal server endpoints.

## Run locally
1. Install Node.js 20+.
2. Copy `.env.example` to `.env`.
3. Set a strong `SESSION_SECRET`, `ADMIN_EMAIL`, and `ADMIN_PASSWORD`.
4. `npm install`
5. `npm start`
6. Open `http://localhost:3000`

Never send PayPal secrets in chat; add them privately as environment variables on the host.
