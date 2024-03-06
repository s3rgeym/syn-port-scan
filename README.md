# SYN-PORT-SCAN

Fast TCP SYN Port Scanner.

```bash
# Install
pipx install syn-port-scan

# Usage
syn-port-scan -h

# Requires root priveleges to send SYN packets
sudo syn-port-scan -a 10.0.0.1 -p 1-2000
```

# Tests

```bash
python -m unittest discover
```
