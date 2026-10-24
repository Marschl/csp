<?php

// Without this the right in package.yml (csp[]) is unknown to the role form and only admins can open the pages.
if (rex::isBackend() && rex::getUser()) {
    rex_perm::register('csp[]');
}

// The header is only sent for the website. The REDAXO backend uses inline scripts itself and is not covered.
if (rex::isFrontend()) {
    csp::boot();
}
