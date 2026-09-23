# This is the GitHub Wiki's source

These `.md` files are written as GitHub Wiki pages (using `[[Page
Name|Page-Name]]` wiki-link syntax) and mirror 1:1 onto
https://github.com/thomasmd321/local-network-toolkit/wiki — `_Sidebar.md`
is GitHub's special persistent-sidebar file, `Home.md` is the wiki's home
page, and every other file is one page named after its filename (dashes
become spaces in the page title).

They live here, committed to the main repo, rather than only in the wiki
itself, because a GitHub wiki is a *separate* git repository
(`local-network-toolkit.wiki.git`) that some automation/CI environments
have no credentials for — keeping the source here means it's never stuck
only inside a wiki-specific clone, and it gets reviewed in the same PRs as
the code it documents.

## Publishing changes to the actual wiki

The wiki has its own git remote — `local-network-toolkit.wiki.git`, not
`local-network-toolkit.git` — editable by anyone with push access to this
repo. Run this from your own machine (or anywhere with normal `git`
credentials for your GitHub account); it does **not** work from a Claude
Code cloud/remote session, see the note at the bottom of this section.

**1. Make sure the wiki exists first.** A repo's wiki has no git remote
at all until at least one page has been created through the web UI —
`git clone` on a wiki that's never been touched fails outright. If
https://github.com/thomasmd321/local-network-toolkit/wiki says "Create
the first page," click that and save anything (even the placeholder
text) before continuing. If it already shows a Home page, skip to step 2.

**2. Clone the wiki repo** (a separate clone from the main repo, into its
own directory):

```
git clone https://github.com/thomasmd321/local-network-toolkit.wiki.git
```

**3. Copy every page across, except this README** (this file documents
`docs/wiki/` for people editing the main repo — it isn't itself a wiki
page, and copying it in would create a stray "README" page on the wiki):

```
cd local-network-toolkit          # the main repo, wherever you have it checked out
for f in docs/wiki/*.md; do
  [ "$(basename "$f")" = "README.md" ] && continue
  cp "$f" ../local-network-toolkit.wiki/
done
```

**4. Commit and push** from inside the wiki clone:

```
cd ../local-network-toolkit.wiki
git add -A
git commit -m "Sync wiki from docs/wiki/"
git push origin master
```

(GitHub wikis default to a `master` branch even when the main repo uses
`main` — check `git branch` if `git push` complains about the branch
name.)

**5. Verify it actually landed**: reload
https://github.com/thomasmd321/local-network-toolkit/wiki and confirm the
sidebar shows the full page list, not just Home.

Alternatively, edit pages directly at
https://github.com/thomasmd321/local-network-toolkit/wiki — just also
update the matching file here afterward so the two don't drift apart.

**Why this can't be done from within a Claude Code cloud session:**
outbound git/HTTP access there is proxied and scoped to this repo
specifically (`repos/{owner}/{repo}/...`-shaped requests only) — a wiki
is a separate, unlisted git repository GitHub's own API has no "repo"
resource for at all, so there's no way to add it to that scope. Reading
(`git clone`) the wiki works there once it's public and initialized
(no credentials needed for a public clone), but *pushing* to it does
not and cannot from that environment — do the actual publish step from
a normal terminal instead.

## Keeping this in sync with the code

Treat `docs/wiki/` the same as `README.md` and `TODO.md`: when a flag is
added, renamed, or removed on either scanner, or a new standalone script
is added, update the matching wiki page(s) in the same change — see
`TODO.md`'s own "Done:" entries for the level of detail expected.
