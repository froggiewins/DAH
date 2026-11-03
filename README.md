# D.A.H. (Digital Art Hub)

One endless shared wall of art with a coordinate system. Anyone can look around. Posting needs an account, pictures can't overlap, admins can ban accounts, repeat offenders are banned automatically, and a live counter tracks the total.

## Setup

1. In your Supabase project, paste all of `supabase.sql` into the SQL Editor and run it. Moderation steps are at the top of that file.
2. In Supabase, set Authentication > URL Configuration > Site URL to the site's address.
3. Put your project URL and publishable key in `config.js`.
4. Publish with GitHub Pages: Settings > Pages > Deploy from a branch > `main` / root.

## Files

- `index.html` is the whole site.
- `config.js` holds the Supabase connection.
- `supabase.sql` creates the tables, rules and image storage.
- `vendor/supabase.js` is the Supabase client (MIT).

Moderation is at `#admin` on the site's address while signed in.
