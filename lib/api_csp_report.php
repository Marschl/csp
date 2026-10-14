<?php

/**
 * Endpoint for CSP violation reports: POST /index.php?rex-api-call=csp_report
 *
 * Browsers send the report without cookies and without a CSRF token, so protection is switched off. In return
 * the endpoint stores nothing but aggregated, trimmed records (see csp_report) and always answers 204.
 */
class rex_api_csp_report extends rex_api_function
{
    protected $published = true;

    public function execute()
    {
        rex_response::cleanOutputBuffers();

        if (rex_request::requestMethod() !== 'post') {
            rex_response::setStatus('405 Method Not Allowed');
            rex_response::setHeader('Allow', 'POST');
            rex_response::sendContent('', 'text/plain');
            exit;
        }

        try {
            // one byte more than allowed, so an oversized body is recognized and dropped by the parser
            $body = (string) stream_get_contents(fopen('php://input', 'r'), csp_report::MAX_BODY + 1);
            foreach (csp_report::parse($body) as $record) {
                csp_report_store::record($record);
            }
        } catch (Throwable $e) {
            rex_logger::logException($e);
        }

        rex_response::setStatus('204 No Content');
        rex_response::sendContent('', 'text/plain');
        exit;
    }
}
