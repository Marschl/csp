<?php

// The header is only sent for the website. The REDAXO backend uses inline scripts itself and is not covered.
if (rex::isFrontend()) {
    csp::boot();
}
