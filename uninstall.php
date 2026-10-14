<?php

// The report table is dropped, the profiles file in redaxo/data/addons/csp/ is configuration and stays.
rex_sql_table::get(rex::getTable('csp_report'))->drop();
