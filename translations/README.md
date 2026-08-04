# EmailEngine Translations

Translations only cover the public UI.

`messages.pot` is the template listing every translatable string found in the source. Each `locale.po`
holds one language's translations of those strings, and the `locale.mo` beside it is the compiled form
that EmailEngine actually loads at runtime, so a `.po` change only takes effect once the `.mo` is
regenerated and committed alongside it.

A locale is served only if it is also listed in [locales.json](locales.json).

## Adding a new translation

1. Create a new translation file using [POEdit](https://poedit.net/download)
2. Click on "Update from POT" option
3. Select [messages.pot](messages.pot) as the source file
4. Add your translations
5. Save file as `locale-name.po` (POEdit should autogenerate `locale-name.mo` as well)
6. Make a pull request or send the po-file to andris@postalsys.com

## Updating translations from the command line

The same job with GNU gettext (`brew install gettext`, or the `gettext` package on Linux). Run these
from the repository root.

Refresh the template first, whenever source strings have been added or changed:

```bash
npm run gettext
```

That rewrites `messages.pot` from the views and JS. It also reorders entries as it goes, so expect a
diff even when no string actually changed - compare the `msgid` lines rather than the line count.

Then merge the template into each catalog and see what is missing:

```bash
cd translations
for loc in en de et fr ja nl pl; do
    msgmerge --update --backup=none --no-fuzzy-matching --quiet $loc.po messages.pot
done

msgattrib --untranslated de.po
```

`msgmerge` reorders entries to match the template, which makes the diff large while leaving existing
translations untouched. `--no-fuzzy-matching` is deliberate: it keeps gettext from guessing a
translation for a new string from a similar old one and marking it fuzzy, which is easy to miss in
review.

Fill in the empty `msgstr` values, then compile and confirm the counts:

```bash
for loc in en de et fr ja nl pl; do
    msgfmt --check --statistics -o $loc.mo $loc.po
done
```

Commit both the `.po` and the `.mo`.

Notes:

- `en.po` is left untranslated on purpose. English is the source language, so an empty `msgstr` falls
  back to the `msgid`, and `msgfmt` reporting it as almost entirely untranslated is expected.
- Match the register each catalog already uses rather than one house style. Today de, et and fr address
  the user formally, ja is polite, and nl and pl are informal.
- Reuse the wording a locale already chose for recurring terms. Checking how it translated
  "Email Account Setup", for instance, settles how to render "setup" elsewhere.
- The strings are extracted without message context, so a bare word like "Expected" cannot be
  disambiguated by a translator. Prefer a short phrase when writing a new one.

To check a page end to end, request it with the locale you want:

```bash
curl -H 'accept-language: de' 'http://127.0.0.1:3000/accounts/new?data=...&sig=...'
```

## Validation error messages

Field validation error message translations can be found and edited from the [joi-messages project](https://github.com/postalsys/joi-messages/tree/master/translations).
