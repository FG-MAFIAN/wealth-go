# Wealth Go

## Run locally
1. Install Node.js 20 or newer.
2. Extract this ZIP and open a terminal in the `wealth-go` folder.
3. Run `npm install`.
4. Copy `.env.example` to `.env` and configure a strong session secret and admin credentials before deployment.
5. Run `npm start`.
6. Visit `http://localhost:3000`.

## VIP package figures
The site lists VIP 1–VIP 7 with the requested investment amounts and daily/30-day projections. The projections are operator-supplied estimates, not guarantees; no returns are automatically credited by this starter. These figures represent 25% daily / 750% over 30 days, which is exceptionally high and may be unsustainable. Verify applicable laws, licensing, and written terms before offering any real investment product.

## Hosting
Use a Node.js host that supports persistent disk/storage for SQLite and uploaded proof files. A static-only host is not enough for this Express backend. Configure environment variables, persistent storage, HTTPS, and backups before going live.
