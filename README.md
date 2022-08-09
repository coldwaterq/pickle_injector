# pickle_injector

### Exploitation
Pickles are broken, if you see one you can easilly plant a backdoor into it using the `inject.py` script.
```bash
python inject.py existingPickle.pt newBackdooredPickle.pt malware.py
```

### Mitigation
If somone wishes to fix the issue, `SecureAlternative.py` shows an example solution for pytorch to save model weights securely.

### Detection
- [Yara Rule created by Medsterr](https://github.com/medsterr/yara/tree/main/python/pickle_injector.py)

### Related Presentation
- [DEFCON Powerpoint Version](https://coldwaterq.com/presentations/ColdwaterQ - BACKDOORING Pickles A decade only made things worse - v1.pptx)
- [DEFCON PDF Version](https://coldwaterq.com/presentations/ColdwaterQ - BACKDOORING Pickles A decade only made things worse - v1.pdf)
- [DEFCON Demo Gif](https://coldwaterq.com/presentations/ColdwaterQ - BACKDOORING Pickles A decade only made things worse - v1 - demo.gif)
