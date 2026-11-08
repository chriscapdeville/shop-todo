# Shop To-Do

Phone app + shop-floor TV board. No dependencies (Node 22+, built-in SQLite).

- `/`  phone app: pick your name, enter your PIN. Toggle **My List** / **Shop Board**.
- `/tv?key=KEY`  read-only big-screen board, refreshes every 10 seconds, no login. Highlights anyone with nothing open ("Free to help").
- Privacy is enforced on the server: private tasks and hidden people are never sent to the TV or to other phones (the board only shows a "+ N private" count so a person with private work doesn't look idle).

## First run
A first user is created: **Chris**, PIN **1234**, whole list hidden from the board. Sign in, open Settings, change the PIN, then add everyone else under People.

## Deploy on Render (same way as the SOP site)
1. Put these files in a private GitHub repo.
2. New Web Service, Docker, add a disk mounted at `/data`.
3. Optional environment variables: `TV_KEY` (the secret in the TV address), `ADMIN_NAME`, `ADMIN_PIN`, `SESSION_SECRET`. If unset, the TV key and session secret are generated and stored on the disk; the TV address prints in the Render logs on startup.
4. Open the TV address in the TV's browser and set it to full screen.

## Run locally
`node --no-warnings server.js` then open http://localhost:3000
