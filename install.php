<?php

rex_sql_table::get(rex::getTable('csp_report'))
    ->ensurePrimaryIdColumn()
    ->ensureColumn(new rex_sql_column('hash', 'char(40)'))
    ->ensureColumn(new rex_sql_column('directive', 'varchar(64)'))
    ->ensureColumn(new rex_sql_column('blocked', 'varchar(255)'))
    ->ensureColumn(new rex_sql_column('path', 'varchar(255)'))
    ->ensureColumn(new rex_sql_column('disposition', 'varchar(16)'))
    ->ensureColumn(new rex_sql_column('sample', 'varchar(255)', true))
    ->ensureColumn(new rex_sql_column('hits', 'int(10) unsigned', false, '1'))
    ->ensureColumn(new rex_sql_column('first_seen', 'datetime'))
    ->ensureColumn(new rex_sql_column('last_seen', 'datetime'))
    ->ensureIndex(new rex_sql_index('hash', ['hash'], rex_sql_index::UNIQUE))
    ->ensure();

// Seed: the first profile that matches every host. Stays untouched when a profiles file exists already.
$file = csp_profiles::file();
if (!is_file($file)) {
    csp_profiles::save(csp_profiles::defaults());
}
