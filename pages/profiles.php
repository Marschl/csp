<?php

$addon = rex_addon::get('csp');
$csrf = rex_csrf_token::factory('csp_profiles');
$file = csp_profiles::file();

// In live mode the backend does not change configuration (no settings, no package management), so the profiles are shown only
$readOnly = rex::isLiveMode();

$yaml = (string) rex_file::get($file, '');
$errors = [];
$saved = false;

if (!$readOnly && rex_post('save', 'bool') && $csrf->isValid()) {
    $yaml = str_replace("\r\n", "\n", rex_post('yaml', 'string', ''));
    try {
        $decoded = rex_string::yamlDecode($yaml);
        [$profiles, $errors] = csp_profiles::normalize($decoded);
        if (!$errors) {
            csp_profiles::save($profiles);
            $yaml = (string) rex_file::get($file, '');
            $saved = true;
        }
    } catch (rex_yaml_parse_exception $e) {
        $errors[] = $e->getMessage();
    }
}

if ($saved) {
    echo rex_view::success(rex_i18n::msg('csp_profiles_saved'));
}
if ($errors) {
    echo rex_view::error(rex_i18n::msg('csp_profiles_invalid') . '<ul><li>' . implode('</li><li>', array_map('rex_escape', $errors)) . '</li></ul>');
}

$problems = $saved || $errors ? [] : csp_profiles::problems();
if ($problems) {
    echo rex_view::warning(rex_i18n::msg('csp_profiles_unreadable') . '<ul><li>' . implode('</li><li>', array_map('rex_escape', $problems)) . '</li></ul>');
}

echo rex_view::info(rex_i18n::msg($readOnly ? 'csp_profiles_live' : 'csp_profiles_intro'));

$field = '<div class="form-group"><label for="csp-yaml">' . rex_i18n::msg('csp_profiles_file') . '</label>'
    . '<textarea class="form-control" id="csp-yaml" name="yaml" rows="22" spellcheck="false" style="font-family:monospace"' . ($readOnly ? ' readonly' : '') . '>' . rex_escape($yaml) . '</textarea></div>';
$body = $readOnly
    ? $field
    : '<form action="' . rex_url::currentBackendPage() . '" method="post">'
        . $csrf->getHiddenField()
        . $field
        . '<button class="btn btn-save" type="submit" name="save" value="1">' . rex_i18n::msg('csp_profiles_save') . '</button>'
        . '</form>';

$fragment = new rex_fragment();
$fragment->setVar('title', rex_i18n::msg('csp_profiles_file'), false);
$fragment->setVar('body', $body, false);
echo $fragment->parse('core/page/section.php');

// Preview of what each profile would send, computed from the saved file
$host = rex_request::server('HTTP_HOST', 'string', '');
$rows = '';
$profiles = csp_profiles::all();
foreach ($profiles as $profile) {
    $policy = csp_profiles::policy($profile);
    $active = csp_profiles::matches($profile, $host);
    $warnings = $policy->warnings();
    $rows .= '<tr' . ($active ? ' class="success"' : '') . '>'
        . '<td><strong>' . rex_escape($profile['name']) . '</strong>' . ($active ? '<br><small>' . rex_i18n::msg('csp_profile_active') . '</small>' : '') . '</td>'
        . '<td>' . rex_escape(implode(', ', $profile['hosts'])) . '</td>'
        . '<td>' . rex_escape($profile['mode']) . ($profile['report'] ? ' + report' : '') . '</td>'
        . '<td><code style="white-space:normal;word-break:break-word">' . rex_escape($policy->toHeader('<nonce>')) . '</code>'
        . ($warnings ? '<br><small class="text-warning">' . implode('<br>', array_map('rex_escape', $warnings)) . '</small>' : '')
        . '</td></tr>';
}
if ($profiles) {
    $table = '<table class="table table-striped table-hover"><thead><tr><th>' . rex_i18n::msg('csp_profile_name') . '</th><th>' . rex_i18n::msg('csp_profile_hosts')
        . '</th><th>' . rex_i18n::msg('csp_profile_mode') . '</th><th>' . rex_i18n::msg('csp_profile_header') . '</th></tr></thead><tbody>' . $rows . '</tbody></table>';
    $fragment = new rex_fragment();
    $fragment->setVar('title', rex_i18n::msg('csp_profiles_preview') . ' · ' . rex_i18n::msg('csp_profiles_current_host') . ': ' . rex_escape($host), false);
    $fragment->setVar('content', $table, false);
    echo $fragment->parse('core/page/section.php');
    if (csp_profiles::find($host) === null) {
        echo rex_view::warning(rex_i18n::msg('csp_profiles_no_match'));
    }
}
