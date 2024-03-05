# SYN-PORT-SCAN

Fast TCP SYN Port Scanner.

```bash
# Install
pipx install syn-port-scan

# Usage
syn-port-scan -h

# Requires root priveleges to send SYN packets
sudo syn-port-scan
```

## Development

```bash
pytest -vs
```

* Use dotenv zsh plugin to set `PYTHONPATH` and run pytest
