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

## Key

AES-256-CFB mit Key `918273645` (eigenständig, nicht kompatibel mit `fsociety.exe`)
