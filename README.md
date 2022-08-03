# pickle_injector

### Exploitation
Pickles are broken, if you see one you can easilly plant a backdoor into it using the `inject.py` script.
```bash
python inject.py existingPickle.pt newBackdooredPickle.pt malware.py
```

### Mitigation
If somone wishes to fix the issue, `SecureAlternative.py` shows an example solution for pytorch to save model weights securely.
