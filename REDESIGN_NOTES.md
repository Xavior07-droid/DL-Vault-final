# Front-end redesign notes

Only templates and static files changed. No routes, models, form field names or backend logic were touched.

- static/css/main.css: rewritten as one design system (tokens, components, app shell, responsive, dark mode)
- templates/base.html: new signed-in layout (sidebar + top search) and cleaner public header/footer
- templates/home.html, login.html, register.html: rewritten in plain language
- Other pages: copy, labels and emoji replaced; structure unchanged

Fonts: Newsreader (headlines) and Figtree (text) via Google Fonts, with system fallbacks.
Behaviour change: the terms checkbox on the register page is no longer pre-ticked.

Added in the second pass: "what to do next" card on the dashboard, "what happens when the time comes" section on the home page, table of contents on legal pages, gentle scroll fade-in (off when reduced motion is requested), small-phone header fix. All colour pairs checked against WCAG AA.
