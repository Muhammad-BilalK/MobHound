# MobHound

MobHound is a modular Android security testing toolkit for APK reverse engineering, dynamic traffic interception, request replay, payload testing, and security scanning.

It is designed for authorized mobile application security testing. Use it only on applications, devices, and networks where you have permission to test.

## Features

- **Intercepter**: capture Android HTTP/HTTPS traffic, configure proxying, install CA certificates, and run Frida-based runtime bypasses.
- **Analyzer**: replay and modify captured requests in a repeater-style workflow.
- **Payloader**: run payload campaigns against marked insertion points in HTTP requests.
- **Scanner**: combine static, dynamic, heuristic, signature, malware, and AI-assisted checks into security findings and reports.
- **Extractor**: unpack/decompile APKs, browse extracted artifacts, and generate pseudocode for easier review.
- **Encoder/Decoder**: transform values such as URL/base64 payloads during testing.

## Repository Contents

Important source files and folders:

```text
main.py                         Main PySide6 GUI application
config.py                       Central configuration loader
mobhound.json                   Default local configuration
mobhound_project.py             Project/session storage helpers
requirements.txt                Python dependencies
mobhound_tools/                 Shared silent tool installer + packaged config
dynamic_analysis/               ADB, mitmproxy, Frida, replay, payloader backend
reverse_engineering/            APK reverse engineering and pseudocode backend
scanner/                        Static/dynamic/AI scanner logic
assets/                         Icons and UI assets
scripts/                        Test and diagnostic scripts
```

## Requirements

- Python 3.10+ recommended
- Windows, Linux, or macOS
- Android emulator or physical Android device
- USB debugging enabled for physical devices
- Internet access on first use so MobHound can download managed tools

MobHound installs Python dependencies from `requirements.txt`. External Android/security tools are handled separately by the silent installer.

## Local Setup

Clone the repository:

```bash
git clone https://github.com/<your-username>/<your-repo>.git
cd <your-repo>
```

Create and activate a virtual environment.

Windows PowerShell:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

Linux/macOS:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install Python requirements:

```bash
pip install -r requirements.txt
```

Run MobHound:

```bash
python main.py
```

## Managed Tool Installation

MobHound recreates it locally when tools are needed. The shared installer checks whether a required tool is already available in the system `PATH` or under `.mobhound_tools/`. If missing, it silently downloads or installs the tool into `.mobhound_tools/`.

Managed tools include:

- Android SDK Platform Tools / `adb`
- `mitmproxy`
- Frida host tools
- Frida server binaries
- JADX
- APKTool
- dex2jar

## Configuration

MobHound loads configuration from `config.py` using this order:

1. explicit config path argument
2. `MOBHOUND_CONFIG` environment variable
3. root `mobhound.json`
4. packaged `mobhound_tools/mobhound.json`
5. `~/.mobhound/config.json`
6. built-in defaults

The default tool directory is:

```text
.mobhound_tools/
```

You can customize paths, ports, scanner options, logging, Frida settings, ADB settings, and mitmproxy settings in `mobhound.json`.

## Recommended Workflow

1. Launch MobHound.
2. Create or select a project.
3. Open `Intercepter`.
4. Connect an emulator or Android device.
5. Generate and install the CA certificate.
6. Set up Frida if runtime bypasses are needed.
7. Start interception and interact with the target app.
8. Send interesting flows to `Analyzer` or `Payloader`.
9. Run `Scanner` for findings and reports.
10. Use `Extractor` for APK-level code and resource review.

## Modules

### Intercepter

The Intercepter module captures Android app traffic and supports runtime bypass setup.

Typical workflow:

1. Connect an emulator or device.
2. Refresh device/app information.
3. Generate and install the MobHound CA certificate.
4. Configure proxy routing.
5. Set up Frida if the app uses SSL pinning or runtime protections.
6. Start interception.
7. Review captured flows in the traffic table.
8. Send selected requests to Analyzer or Payloader.

Useful checks if traffic does not appear:

- Confirm the device proxy points to the MobHound host and port.
- Confirm the CA certificate is installed and trusted.
- Enable SSL pinning bypass for pinned apps.
- Restart the target app after enabling hooks.
- Check device/app logs from the UI.

### Analyzer

Analyzer is a request replay and editing module.

Typical workflow:

1. Send a captured request from Intercepter.
2. Edit the URL, method, headers, or body.
3. Send the modified request.
4. Compare responses.
5. Iterate across multiple request tabs.

Use it for manual API testing, authorization checks, parameter tampering, and response comparison.

### Payloader

Payloader runs Intruder-style payload attacks against marked request positions.

Typical workflow:

1. Load or send a request into Payloader.
2. Mark one or two insertion points.
3. Add payloads manually or load them from a file.
4. Configure delay, timeout, and encoding options.
5. Start the attack.
6. Review response differences and status results.

Marker behavior:

- The first marker uses payload List 1.
- The second marker uses payload List 2.
- One marker runs a single-list replacement attack.
- Two markers can run payload combinations.

### Scanner

Scanner produces prioritized security findings from available APK, static, dynamic, and AI signals.

Pipeline:

1. Ingest reverse engineering output.
2. Run static detectors.
3. Include dynamic traffic/events when available.
4. Apply heuristic/signature checks.
5. Apply AI-assisted risk scoring when enabled.
6. Correlate and de-duplicate findings.
7. Generate reports.

Outputs can include JSON, HTML, and PDF reports depending on configuration.

### Extractor

Extractor handles APK reverse engineering and code review support.

Typical workflow:

1. Select an APK.
2. Run extraction/decompilation.
3. Browse manifests, resources, smali, and decompiled code.
4. Open files in the viewer.
5. Generate pseudocode where supported.
6. Send context into Scanner if needed.

Extractor uses managed reverse engineering tools such as JADX, APKTool, and dex2jar.

### Encoder/Decoder

Encoder/Decoder provides quick transformations for testing and payload preparation.

Common uses:

- URL encoding/decoding
- Base64 encoding/decoding
- Token or payload formatting
- Quick conversion while testing requests

## Dynamic Analysis Notes

Proxy host values depend on the environment:

- Android Emulator commonly uses `10.0.2.2` to reach the host machine.
- Genymotion commonly uses `10.0.3.2`.
- Physical devices usually need the host machine LAN IP.

For HTTPS interception:

1. Start MobHound interception.
2. Install the generated CA certificate on the Android device.
3. Ensure device proxy settings point to MobHound.
4. Enable SSL pinning bypass when required.

## Troubleshooting

### App Starts But Tools Are Missing

MobHound should silently install managed tools into `.mobhound_tools/`. If installation fails:

- Check internet access.
- Check `.mobhound_tools/install.log`.
- Confirm antivirus/firewall is not blocking downloads.
- Run the app from a terminal to see Python errors.

### No Device Found

- Enable USB debugging.
- Confirm the emulator is running.
- Try `adb devices`.
- Reconnect the device and accept the Android debugging prompt.

### HTTPS Traffic Fails

- Reinstall the MobHound CA certificate.
- Restart the target app.
- Enable SSL pinning bypass.
- Confirm the device proxy host/port are correct.

### Reports Are Missing

- Confirm the project directory is writable.
- Run Scanner again after Extractor or Intercepter has produced data.
- Check logs under the local `logs/` folder if enabled.

## GitHub Upload Notes

Recommended files/folders to commit:

```text
README.md
.gitignore
main.py
config.py
mobhound.json
mobhound_project.py
requirements.txt
mobhound_tools/
assets/
dynamic_analysis/
reverse_engineering/
scanner/
scripts/
```

## Security and Legal Notice

MobHound is intended for defensive security research, authorized penetration testing, and mobile application assessment. Do not use it against applications, systems, networks, or devices without explicit permission.

