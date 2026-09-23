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

The wiki has its own git remote, editable by anyone with push access to
this repo:

```
git clone https://github.com/thomasmd321/local-network-toolkit.wiki.git
cp docs/wiki/*.md local-network-toolkit.wiki/
cd local-network-toolkit.wiki
git add -A
git commit -m "Sync wiki from docs/wiki/"
git push
```

(Or edit pages directly at https://github.com/thomasmd321/local-network-toolkit/wiki
— just also update the matching file here afterward so the two don't
drift apart.)

## Keeping this in sync with the code

Treat `docs/wiki/` the same as `README.md` and `TODO.md`: when a flag is
added, renamed, or removed on either scanner, or a new standalone script
is added, update the matching wiki page(s) in the same change — see
`TODO.md`'s own "Done:" entries for the level of detail expected.
