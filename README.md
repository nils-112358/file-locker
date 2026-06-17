# Lock & Unlock

Sicheres Versteck für Dateien. Erstellt einen Ordner `stuff`, in dem alle Dateien mit AES-256 verschlüsselt werden.

## Verwendung

```
lock.exe             # 1. Aufruf: erstellt stuff\  2. Aufruf: verschlüsselt
unlock.exe           # Entschlüsselt alles in stuff\
```

## Ablauf

1. `lock.exe` ausführen → erstellt Ordner `stuff` (falls nicht vorhanden)
2. Dateien in `stuff\` ablegen
3. `lock.exe` erneut ausführen → alle Dateien werden verschlüsselt + `.locked` angehängt
4. `unlock.exe` ausführen → alle `.locked`-Dateien werden entschlüsselt

## Test

`test.gif.locked` ist eine verschlüsselte Testdatei – mit `unlock.exe` entschlüsseln, probier es aus und lass dich überraschen.

## Key

AES-256-CFB mit Key `918273645`
