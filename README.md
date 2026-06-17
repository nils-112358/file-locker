# Lock & Unlock

Sicheres Versteck für Dateien. Erstellt einen Ordner `stuff`, in dem alle Dateien mit AES-256 verschlüsselt werden.

## Verwendung

```
lock.exe             # 1. Aufruf: erstellt stuff\ + key.bin   2. Aufruf: verschlüsselt
unlock.exe           # Entschlüsselt alles in stuff\
```

## Ablauf

1. `lock.exe` ausführen → erstellt Ordner `stuff` + `key.bin` mit zufälligem Schlüssel
2. Dateien in `stuff\` ablegen
3. `lock.exe` erneut ausführen → alle Dateien werden verschlüsselt (`.locked`) und geschreddert
4. `unlock.exe` ausführen → alle `.locked`-Dateien werden entschlüsselt, Original geschreddert

## Features

- **AES-256-CFB** mit zufälligem Schlüssel (pro Installation einzigartig, gespeichert in `key.bin`)
- **Shreddern**: 3-faches Überschreiben mit Zufallsdaten vor dem Löschen
- **C++17** / plattformunabhängig (Windows, Linux, macOS)

## Test

`test.gif.locked` ist eine verschlüsselte Testdatei – mit `unlock_old.exe` (nutzt keinen random key) entschlüsseln, probier es aus und lass dich überraschen.

## Kompilieren (Linux/macOS)

```
g++ -std=c++17 -o lock lock.cpp -lcryptopp
g++ -std=c++17 -o unlock unlock.cpp -lcryptopp
```
