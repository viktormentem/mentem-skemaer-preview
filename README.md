# mentem-skemaer — localStorage-only klient-variant

⚠️ **IKKE prod, IKKE server-preview.** Dette er den **G3-frie rigtig-klient-variant**:
data lagres KUN i klientens egen browser (localStorage) og forlader aldrig enheden
undtagen som én krypteret fil, klienten selv sender til psykologen.

- `LOCAL_ONLY = true` er **bagt ind i HTML'en** → server-sync er strukturelt umulig
  (draftBase tom, `?api` ignoreret) → robust mod param-tab (reload/bookmark).
- Ingen Cloudflare-draftstore, ingen `{BASE}`, ingen databehandler → **springer G3 over**.
- Privatlivstekst = v1 (localStorage: "mistes ved browser-ryd / enheds-skift").
- Ugentlig ikke-terminal "Send opdatering" + terminal "Afslut og send".

URL: https://viktormentem.github.io/mentem-skemaer-lokal/?s=soevndagbog

Kilde: mentem-skemaer @ bac139f (LOCAL_ONLY-transformeret). Afsendelse til rigtig
klient = Viktor go-live-beslutning + klient-samtykke (Art. 9(2)(h)).
