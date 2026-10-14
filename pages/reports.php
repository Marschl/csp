<?php

$csrf = rex_csrf_token::factory('csp_reports');

if (rex_get('func', 'string') === 'delete' && $csrf->isValid()) {
    $id = rex_get('id', 'int', 0);
    csp_report_store::delete($id > 0 ? $id : null);
    echo rex_view::success(rex_i18n::msg('csp_reports_deleted'));
}

echo rex_view::info(rex_i18n::msg('csp_reports_intro'));

$total = csp_report_store::count();
if ($total >= csp_report_store::MAX_ROWS) {
    echo rex_view::warning(rex_i18n::msg('csp_reports_limit'));
}

$rows = rex_sql::factory()->getArray('SELECT * FROM ' . csp_report_store::table() . ' ORDER BY hits DESC, last_seen DESC LIMIT 500');
if (!$rows) {
    echo rex_view::info(rex_i18n::msg('csp_reports_empty'));
    return;
}

$body = '';
foreach ($rows as $row) {
    $deleteUrl = rex_url::currentBackendPage(['func' => 'delete', 'id' => $row['id']] + $csrf->getUrlParams());
    $body .= '<tr>'
        . '<td>' . rex_escape($row['directive']) . '</td>'
        . '<td>' . rex_escape($row['blocked'] === '' ? '(self)' : $row['blocked']) . '</td>'
        . '<td>' . rex_escape($row['path']) . '</td>'
        . '<td>' . rex_escape($row['disposition']) . '</td>'
        . '<td class="text-right">' . (int) $row['hits'] . '</td>'
        . '<td>' . rex_escape($row['last_seen']) . '</td>'
        . '<td><code>' . rex_escape((string) $row['sample']) . '</code></td>'
        . '<td><a href="' . $deleteUrl . '">' . rex_i18n::msg('csp_reports_delete') . '</a></td>'
        . '</tr>';
}

$table = '<table class="table table-striped table-hover"><thead><tr>'
    . '<th>' . rex_i18n::msg('csp_reports_directive') . '</th><th>' . rex_i18n::msg('csp_reports_blocked') . '</th><th>' . rex_i18n::msg('csp_reports_path') . '</th>'
    . '<th>' . rex_i18n::msg('csp_reports_disposition') . '</th><th class="text-right">' . rex_i18n::msg('csp_reports_hits') . '</th>'
    . '<th>' . rex_i18n::msg('csp_reports_last') . '</th><th>' . rex_i18n::msg('csp_reports_sample') . '</th><th></th>'
    . '</tr></thead><tbody>' . $body . '</tbody></table>';

$deleteAll = rex_url::currentBackendPage(['func' => 'delete'] + $csrf->getUrlParams());
$fragment = new rex_fragment();
$fragment->setVar('title', rex_i18n::msg('csp_reports') . ' (' . $total . ')', false);
$fragment->setVar('content', $table, false);
$fragment->setVar('footer', '<a class="btn btn-delete" href="' . $deleteAll . '" data-confirm="' . rex_escape(rex_i18n::msg('csp_reports_confirm_all')) . '">' . rex_i18n::msg('csp_reports_delete_all') . '</a>', false);
echo $fragment->parse('core/page/section.php');
