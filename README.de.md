# CSP – Content Security Policy für REDAXO

Sendet einen `Content-Security-Policy`-Header für die Website (nicht fürs Backend), gewählt nach Host-Name, samt
Report-Endpunkt. So lässt sich eine Policy erst beobachten und dann scharf stellen.

- **Profile pro Host** (`dev`, `review`, `live`): Modus `off`, `report-only` oder `enforce`
- **Die Konfiguration ist eine Datei**, `redaxo/data/addons/csp/profiles.yml`. Sie gehört ins Projekt-Repository und
  reist mit dem Deploy. Die Backend-Seite bearbeitet dieselbe Datei und prüft vor dem Speichern.
- **Nonce pro Request** mit korrekt quotiertem Header-Wert (`'nonce-…'`)
- **Verstoß-Berichte**, aggregiert gespeichert, ohne IP-Adresse und User-Agent
- Keine Abhängigkeiten. Benötigt REDAXO 5.18+, PHP 8.1+.

## Profile

```yaml
profiles:
    -
        name: Live
        hosts: [example.org, www.example.org]
        mode: enforce            # off | report-only | enforce
        report: false            # Verstöße an den Report-Endpunkt senden
        policy:
            - "default-src 'self'"
            - "img-src 'self' data:"
            - "script-src 'self' 'nonce'"
    -
        name: Alles andere
        hosts: ['*']
        mode: report-only
        report: true
        policy:
            - "default-src 'self'"
```

Es gewinnt das erste Profil, dessen Muster auf den Host passt (`*` und `?` funktionieren, der Port wird ignoriert).
Passt keins, ist `mode: off` gesetzt oder ist die Datei ungültig, gibt es **keinen Header**. Eine kaputte Datei legt die
Website nie lahm, schaltet aber still die Policy ab. Deshalb steht der Fehler im REDAXO-Log und auf der Backend-Seite.

Jede Policy-Zeile ist eine Direktive in Header-Schreibweise. Schlüsselwörter dürfen ohne Anführungszeichen stehen.
`'nonce'` steht für den Nonce des Requests. Bewusst abgelehnt werden: ein fester `'nonce-abc'` oder ein unquotiertes
`nonce-abc` (Browser würden es als Host-Namen lesen), Zeichen, die die Direktive beenden oder den Header aufspalten (`;`, `,`,
Leerraum, Zeilenumbrüche), unbekannte Direktiven und `'none'` zusammen mit weiteren Quellen.

Kein Fehler, aber eine Warnung in der Vorschau: `'unsafe-inline'` neben Nonce, Hash oder `'strict-dynamic'`. Dann
**ignorieren** Browser `'unsafe-inline'`, und jedes Inline-Skript ohne Nonce wird blockiert.

> Die Profildatei kommt aus dem Projekt. Wird das Backend auf dem Live-Server benutzt, überschreibt der nächste Deploy
> die Änderung mit der Datei aus dem Repository.

## Einführung: erst beobachten, dann erzwingen

1. Die neue Policy in ein Profil mit `mode: report-only` und `report: true` schreiben.
2. Die Website durchklicken. Verstöße erscheinen unter *Berichte* (Direktive, blockierter Origin, Seitenpfad, Anzahl).
3. Die Website anpassen oder die Policy erweitern, bis die Liste ruhig ist.
4. Das Profil auf `enforce` stellen.

Berichte gehen per `report-uri` (alle Browser) und `report-to` / `Reporting-Endpoints` (Chromium, verzögert und gebündelt).

## Nonce

```php
<script <?= csp::nonceAttr() ?>>…</script>   // nonce="…" oder nichts
echo csp::nonce();                              // der Wert, leer solange die Policy kein 'nonce' enthält
```

Ein Nonce ändert sich mit jedem Request. Seiten mit Nonce dürfen nicht aus einem Voll-Seiten-Cache kommen.

## Policy aus Code erweitern

```php
csp::addPolicy('img-src', 'https://tiles.example.org');
```

Der Header geht kurz vor der Ausgabe raus, Module und Templates können also noch beim Rendern Quellen ergänzen.
Ungültige Eingaben werfen im Debug-Modus eine Exception und werden sonst geloggt.

## Report-Endpunkt und Datenschutz

`POST /index.php?rex-api-call=csp_report` nimmt `application/csp-report` und `application/reports+json` an und antwortet
immer mit `204`. Gespeichert wird nur dies, eine Zeile je Kombination: verletzte Direktive, **Origin** der blockierten
Quelle, **Pfad** der Seite (ohne Host, Query und Fragment, denn Queries können Tokens enthalten), Art und eine Codeprobe
von 80 Zeichen, dazu ein Zähler. Nicht gespeichert werden IP-Adresse, User-Agent, Referrer und vollständige URLs.
Meldungen von Browser-Erweiterungen werden verworfen. Bodies über 16 KB werden ignoriert, und die Tabelle wächst nicht über
2 000 Zeilen (bestehende Zeilen zählen weiter hoch). Jeder darf an den Endpunkt senden, die Zahlen sind deshalb Hinweise
und keine Statistik.

Berichte löschst du im Backend unter *Berichte*. Das Deinstallieren entfernt die Tabelle und lässt die Profildatei stehen.

## Tests

```bash
php tests/run.php
```

Ohne Framework und ohne REDAXO-Start. Sie decken den Header-Builder, den Profil-Textparser und den Report-Parser ab.

## Lizenz

MIT, siehe `LICENSE`.
