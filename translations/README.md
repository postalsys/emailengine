# EmailEngine Translations

Translations only cover the public UI.

## Adding a new translation

1. Create a new translation file using [POEdit](https://poedit.net/download)
2. Click on "Update from POT" option
3. Select [messages.pot](messages.pot) as the source file
4. Add your translations
5. Save file as `locale-name.po` (POEdit should autogenerate `locale-name.mo` as well)
6. Make a pull request or send the po-file to andris@postalsys.com

## Validation error messages

Field validation error message translations can be found and edited from the [joi-messages project](https://github.com/postalsys/joi-messages/tree/master/translations).
