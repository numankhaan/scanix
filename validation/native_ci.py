"""Run regular regressions with the actual built native binary (no raw privileges)."""
import os
import sys
from pathlib import Path
import unittest

if __name__=='__main__':
    root=Path(__file__).resolve().parents[1]
    sys.path.insert(0,str(root))
    binary=root/'native'/'target'/'release'/('scanix-engine.exe' if os.name=='nt' else 'scanix-engine')
    if not binary.is_file():
        raise SystemExit('Build the release native binary before native_ci.py')
    os.environ['SCANIX_NATIVE_ENGINE']=str(binary)
    tests=unittest.defaultTestLoader.discover(str(root/'scanix'/'tests'))
    raise SystemExit(0 if unittest.TextTestRunner(verbosity=2).run(tests).wasSuccessful() else 1)
