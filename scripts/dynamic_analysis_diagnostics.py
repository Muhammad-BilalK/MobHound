"""Runtime diagnostics for dynamic_analysis components.

Run this script locally on the host where you plan to run dynamic analysis. It
performs non-invasive checks for external binaries (adb, mitmproxy, frida) and
verifies mitmproxy CA presence. It intentionally avoids performing ADB or
device-affecting operations.
"""
from pathlib import Path
import shutil
import json
import sys

ROOT = Path(__file__).resolve().parent.parent

def check_binaries():
    bins = ["adb", "mitmdump", "mitmproxy", "frida", "frida-ps"]
    found = {b: shutil.which(b) for b in bins}
    return found

def check_mitm_ca():
    cert = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.cer"
    return cert.exists(), str(cert)

def quick_mitm_test():
    """Attempt to initialize MitmProxyInterceptor without adb by providing
    a minimal dummy connector and checking mitm binary resolution and CA.
    This does not start ADB operations or modify devices.
    """
    try:
        import dynamic_analysis as da
    except Exception as e:
        return {"ok": False, "error": f"Failed to import dynamic_analysis: {e}"}

    class Dummy:
        def __init__(self):
            self.managed_tools_dir = ROOT / ".mobhound_tools_diagnostics"

    try:
        mitm = da.MitmProxyInterceptor(Dummy(), auto_install_mitmproxy=False)
    except Exception as e:
        return {"ok": False, "error": f"MitmProxyInterceptor init failed: {e}"}

    ca_exists, ca_path = check_mitm_ca()
    return {"ok": True, "mitm_bin": mitm.mitm_bin, "ca_exists": ca_exists, "ca_path": ca_path}

def main():
    print("MobHound dynamic analysis diagnostics")
    print("Checking external binaries...")
    bins = check_binaries()
    print(json.dumps(bins, indent=2))

    print("\nChecking mitmproxy CA certificate...")
    ca_exists, ca_path = check_mitm_ca()
    print(f"mitm CA present: {ca_exists} ({ca_path})")

    print("\nProbing mitmproxy initialization (no adb calls)...")
    mitm_probe = quick_mitm_test()
    print(json.dumps(mitm_probe, indent=2))

    # Guidance
    print("\nGuidance:")
    if not bins.get("adb"):
        print("- adb not found on PATH. Install Android SDK platform-tools or enable auto-download.")
    if not bins.get("frida") or not bins.get("frida-ps"):
        print("- frida host tools not found. The FridaManager can auto-install frida-tools into a managed venv, or install frida-tools system-wide (pip install frida-tools frida).")
    if not bins.get("mitmdump") and not bins.get("mitmproxy"):
        print("- mitmproxy not found. The MitmProxyInterceptor can auto-install mitmproxy into a managed venv, or install mitmproxy system-wide (pip install mitmproxy).")

    print("\nNote: To fully validate device interactions (ADB, frida-server push/start, certificate installation), run the diagnostics on the machine with an attached emulator/device and re-run with network access enabled.")

if __name__ == '__main__':
    sys.exit(0 if main() is None else 0)
