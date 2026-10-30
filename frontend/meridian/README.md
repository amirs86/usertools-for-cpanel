# Meridian theme (not supported yet)

Meridian is cPanel's opt-in theme introduced in v138. cPanel has not yet
published developer documentation for third-party Meridian plugins (page
wrapper, install.json format, hub placement), so UserTools ships Jupiter
pages only.

Once that documentation exists, this directory will hold thin Meridian
adapters (`user_tools/*.html.tt`) wrapping the shared page bodies in
`frontend/shared/`. The shared bodies already contain no theme-specific
markup. No adapter will be guessed from the theme's internals.
