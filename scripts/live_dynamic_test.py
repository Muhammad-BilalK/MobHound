"""Live test script for `dynamic_analysis` against an attached emulator/device.

USAGE:
  python scripts/live_dynamic_test.py [--target IP:PORT] [--serial SERIAL] [--yes]

This script will perform the following (with confirmation prompts unless --yes is given):
 - Connect to adb (or auto-download if enabled)
 - Select an emulator/device
 - Run health checks
 - Ensure mitmproxy CA exists (generate if needed)
 - Push and open CA installer on device (may require user interaction on device)
 - Configure device proxy and start mitmproxy (will launch a local mitmdump)
 - Optionally push and start frida-server and verify connection

Be aware: this script will push files to the device and start processes on it (frida-server,
mitmproxy-related settings). Run only on emulators you control.
"""
import argparse
import time
import sys
from pathlib import Path

def ask(prompt: str, default: bool = False, assume_yes: bool = False) -> bool:
    if assume_yes:
        print(f"[ASSUME YES] {prompt}")
        return True
    resp = input(f"{prompt} [{'Y/n' if default else 'y/N'}]: ")
    if not resp:
        return default
    return resp.strip().lower().startswith('y')

def main():
    parser = argparse.ArgumentParser(description='Live dynamic_analysis tester')
    parser.add_argument('--target', help='Optional adb connect target (host:port)')
    parser.add_argument('--serial', help='Optional exact device serial to use')
    parser.add_argument('--no-auto-download-adb', action='store_true', help='Disable automatic adb download')
    parser.add_argument('--yes', action='store_true', help='Assume yes to prompts')
    parser.add_argument('--skip-frida', action='store_true', help='Skip frida server push/start')
    args = parser.parse_args()

    assume_yes = args.yes

    try:
        import dynamic_analysis as da
    except Exception as e:
        print('Failed to import dynamic_analysis:', e)
        return 2

    print('Creating AndroidEmulatorConnector...')
    connector = da.AndroidEmulatorConnector(auto_download_adb=not args.no_auto_download_adb)
    try:
        connector.start_server()
    except Exception as e:
        print('Failed to start adb server:', e)
        return 3

    if args.target:
        try:
            print('Connecting to target', args.target)
            print(connector.connect(args.target))
        except Exception as e:
            print('adb connect failed:', e)
            return 4

    device = connector.select_emulator(preferred_serial=args.serial)
    if not device:
        print('No device/emulator selected. Run an emulator and retry.')
        return 5

    print(f"Selected device: {device.serial} (emulator={device.is_emulator})")

    # Health check
    health = connector.run_health_check(device.serial)
    print('Health:', 'OK' if health.ok else 'FAILED')
    for k, v in health.details.items():
        print(' ', k, v)

    # Mitmproxy flow
    mitm = da.MitmProxyInterceptor(connector)

    # Ensure CA exists
    ca_path = Path.home() / '.mitmproxy' / 'mitmproxy-ca-cert.cer'
    if not ca_path.exists():
        if not ask('mitm CA missing — generate it now? (this will briefly start mitmdump locally)', False, assume_yes):
            print('Skipping CA generation — mitm interception may fail')
        else:
            try:
                print('Generating CA...')
                p = mitm.generate_ca_certificate()
                print('Generated CA at', p)
            except Exception as e:
                print('CA generation failed:', e)
                return 6

    # Install CA on device
    if ask('Push and open CA installer on device now? (this will open the installer UI on the device)', False, assume_yes):
        try:
            cert = mitm.generate_ca_certificate() if not ca_path.exists() else ca_path
            remote = mitm.install_ca_on_device(device.serial, cert)
            print('Pushed cert to', remote)
            print('Please accept/install the certificate on the device UI if prompted.')
        except Exception as e:
            print('Failed to install CA on device:', e)
            # continue — some setups allow manual install

    # Start mitmproxy and set device proxy
    if ask('Start mitmproxy and set device proxy now?', True, assume_yes):
        try:
            proxy_host = mitm.start(device)
            print('mitmproxy started. Proxy host for device:', proxy_host, 'port:', mitm.port)
            print('Flow stats:', mitm.get_flow_statistics())
        except Exception as e:
            print('Failed to start mitmproxy:', e)
            # collect addon debug log
            print('Addon debug log:')
            print(mitm.get_addon_debug_log())
            return 7

    # Frida setup
    if not args.skip_frida and ask('Push and start frida-server on device? (requires root on some images)', False, assume_yes):
        try:
            frida = da.FridaManager(connector)
            print('Detected frida host tool at', frida.frida_bin)
            if not ask('Proceed to push and start frida-server on device? This will modify device state.', False, assume_yes):
                print('Skipping frida push/start')
            else:
                print('Setting up device frida-server...')
                res = frida.setup_device_server(device.serial)
                print('Frida setup result:', res)
        except Exception as e:
            print('Frida setup failed:', e)

    print('\nLive test finished. You may interact with the app on the emulator to generate traffic now.')
    print('When done, cleanup (mitm stop, frida cleanup) will be needed.')

    if ask('Stop mitmproxy and cleanup now?', True, assume_yes):
        try:
            mitm.stop(device.serial)
            print('mitmproxy stopped and proxy cleared on device')
        except Exception as e:
            print('Error stopping mitm:', e)

    return 0

if __name__ == '__main__':
    sys.exit(main())
