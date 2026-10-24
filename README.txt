CSP – Content Security Policy

Sendet einen Content-Security-Policy-Header für die Website (nicht fürs Backend), gewählt nach Host-Name, samt Report-Endpunkt. So lässt sich eine Policy erst beobachten und dann scharf stellen.

FUNKTIONEN

- Profile pro Host (dev, review, live) mit den Modi off, report-only und enforce
- Die Konfiguration ist eine Datei (redaxo/data/addons/csp/profiles.yml), die ins Projekt-Repository gehört und mit dem Deploy reist. Die Backend-Seite bearbeitet dieselbe Datei und prüft sie vor dem Speichern, samt Vorschau des Headers je Profil
- Nonce pro Request, korrekt quotiert ('nonce-…'), im Template mit csp::nonceAttr()
- Policy aus Code erweitern: csp::addPolicy('img-src', 'https://tiles.example.org')
- Prüfung der Eingaben: kein Header-Splitting, keine festen Nonces, unbekannte Direktiven werden abgelehnt, Warnung bei 'unsafe-inline' neben Nonce oder Hash
- Verstoß-Berichte (report-uri und report-to), aggregiert gespeichert, ohne IP-Adresse und User-Agent, Berichte von Browser-Erweiterungen werden verworfen

EINSTIEG

Nach der Installation liegt ein Profil "Default" für alle Hosts vor, im Modus report-only mit Berichten. Es beobachtet nur und blockiert nichts. Richtlinie anpassen, unter "Berichte" die Verstöße ansehen, dann auf enforce umstellen.

VORAUSSETZUNGEN

REDAXO 5.21.4 oder neuer, PHP 8.1 oder neuer. Keine weiteren Addons. Ältere REDAXO-Versionen sind nicht getestet und nicht unterstützt.

HINWEISE

- Eine ungültige oder fehlende profiles.yml bedeutet: kein Header. Der Fehler steht im REDAXO-Log und im Backend.
- Mit live_mode: true in der config.yml von REDAXO zeigt das Backend die Profile nur an. Die Datei dann im Projekt (Deploy) oder direkt auf dem Server (FTP/SFTP) ändern, die Änderung gilt sofort.
- Seiten mit Nonce dürfen nicht aus einem Full-Page-Cache ausgeliefert werden.
- Jeder darf an den Report-Endpunkt senden. Die Zahlen sind Hinweise, keine Statistik.
- Beim Deinstallieren wird die Tabelle der Berichte gelöscht, die Datei profiles.yml bleibt erhalten.

Feedback ist willkommen, bitte als Issue auf GitHub: https://github.com/Marschl/csp/issues

Lizenz: MIT
