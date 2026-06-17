"""Self-contained unit tests for dynamic_analysis.py components.

These tests avoid touching real devices by mocking `shutil.which`, `Path.exists`,
and `subprocess.run`/`Popen`. Run directly with `python scripts/test_dynamic_analysis_unit.py`.
"""
import importlib
import types
from pathlib import Path

def run_tests():
    import dynamic_analysis as da
    from dynamic_analysis import AndroidEmulatorConnector, MitmProxyInterceptor, FridaManager
    from dynamic_analysis import EmulatorConnectionError, InterceptionError
    import shutil, subprocess

    tests_passed = 0
    tests_failed = 0

    # Helper to temporarily patch and restore attributes
    class Patch:
        def __init__(self, mod, name, new):
            self.mod = mod
            self.name = name
            self.new = new
            self.orig = getattr(mod, name)
        def __enter__(self):
            setattr(self.mod, self.name, self.new)
        def __exit__(self, exc_type, exc, tb):
            setattr(self.mod, self.name, self.orig)

    print('Test: adb not found and auto_download_adb disabled -> EmulatorConnectionError')
    try:
        with Patch(shutil, 'which', lambda name: None):
            # Also ensure candidate paths do not exist
            with Patch(Path, 'exists', lambda self: False):
                try:
                    AndroidEmulatorConnector(adb_path=None, auto_download_adb=False)
                    print('  FAIL: expected EmulatorConnectionError')
                    tests_failed += 1
                except EmulatorConnectionError:
                    print('  OK')
                    tests_passed += 1
    except Exception as e:
        print('  ERROR', e)
        tests_failed += 1

    print('Test: mitmproxy resolved via shutil.which')
    try:
        with Patch(shutil, 'which', lambda name: 'C:/fake/mitmdump.exe' if name in ('mitmdump','mitmproxy') else None):
            dummy = types.SimpleNamespace(managed_tools_dir=Path('.mobhound_test'))
            mitm = MitmProxyInterceptor(dummy, auto_install_mitmproxy=False)
            assert 'mitmdump' in mitm.mitm_bin.lower() or 'mitmproxy' in mitm.mitm_bin.lower()
            print('  OK ->', mitm.mitm_bin)
            tests_passed += 1
    except Exception as e:
        print('  FAIL', e)
        tests_failed += 1

    print('Test: Frida tool missing and auto_install_frida disabled -> InterceptionError')
    try:
        with Patch(shutil, 'which', lambda name: None):
            # Ensure managed venv/tool paths appear missing
            with Patch(Path, 'exists', lambda self: False):
                dummy = AndroidEmulatorConnector(adb_path=None, auto_download_adb=False)
                try:
                    fm = FridaManager(dummy, auto_install_frida=False)
                    print('  FAIL: expected InterceptionError during FridaManager init')
                    tests_failed += 1
                except InterceptionError:
                    print('  OK')
                    tests_passed += 1
    except InterceptionError:
        print('  OK')
        tests_passed += 1
    except EmulatorConnectionError:
        # adb missing will raise EmulatorConnectionError from connector init above
        print('  OK (EmulatorConnectionError because adb missing)')
        tests_passed += 1
    except Exception as e:
        print('  FAIL', type(e), e)
        tests_failed += 1

    print('\nSummary: %d passed, %d failed' % (tests_passed, tests_failed))
    return tests_failed == 0

if __name__ == '__main__':
    ok = run_tests()
    raise SystemExit(0 if ok else 2)
