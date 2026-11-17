"""Explicitly authorized, credential-free Android startup check in a new isolated directory."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import time

ADB = r"D:\APPs\platform-tools\adb.exe"
SERIAL = "35d2186334eaabff"
TARGET = "/data/local/tmp/device-agent-api31-20261027"
EXPECTED_SHA = "3fed9af997ac417eeca7199c1ef3d2b01f7fbe4e709051df258a3d4d64ced0a6"
ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "artifacts/android-api31-20261027"
PREVIEW = ROOT / "tmp/android-build/smoke-preview"


def execute():
    report = {"started_utc": datetime.now(timezone.utc).isoformat(), "device": SERIAL,
              "target": TARGET, "board_write_started": False, "launched": False,
              "commands": [], "private_key_or_token_uploaded": False}

    def save():
        (OUTPUT / "smoke-result.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    def adb(args, check=True, timeout=20, input=None):
        process = subprocess.run([ADB, "-s", SERIAL] + args, input=input, capture_output=True,
                                 text=True, encoding="utf-8", errors="replace", timeout=timeout)
        report["commands"].append({"args": args, "rc": process.returncode})
        if check and process.returncode:
            raise RuntimeError("ADB command failed: " + repr(args) + "; " + process.stderr.strip())
        return process

    def shell(command, check=True):
        return adb(["shell", command], check=check)

    def snapshot():
        return {
            "logagent_state": shell("getprop init.svc.logagent").stdout.strip(),
            "vendor_logagent_state": shell("getprop init.svc.vendor.logagent").stdout.strip(),
            "init_rc_sha256": shell("sha256sum /vendor/etc/init/vendor.logagent.rc").stdout.split()[0],
            "business_sn_property": shell("getprop persist.NX_DEVIECE_SN").stdout.strip(),
            "runtime_directory_metadata": shell("ls -ldZ /data/vendor/logagent").stdout.strip(),
        }

    try:
        binary = OUTPUT / "device-agent"
        assert not binary.is_symlink() and hashlib.sha256(binary.read_bytes()).hexdigest() == EXPECTED_SHA
        expected_config = {
            "device-agent.conf": {"environment": "local"},
            "device-agent.local.conf": {
                "device": "ANDROID-ARM64-SMOKE-001", "host": "127.0.0.1", "port": "65534",
                "sources-config": "log-sources.json", "state-dir": "state", "work-dir": "work", "log-file": "agent.log"},
        }
        for name, expected in expected_config.items():
            path = PREVIEW / name
            assert not path.is_symlink()
            actual = dict(line.strip().split("=", 1) for line in path.read_text().splitlines() if line.strip())
            assert actual == expected, "Unexpected test configuration"
        source = json.loads((PREVIEW / "log-sources.json").read_text())
        assert source == {"log_sources": [{"source_id": "smoke", "path": "empty-test-logs", "recursive": False,
                                          "file_patterns": ["*.log"], "filename_date_formats": ["%Y-%m-%d"]}]}
        assert shell("id -u").stdout.strip() == "2000"
        assert shell("getprop ro.serialno").stdout.strip() == SERIAL
        assert shell("getprop ro.product.cpu.abi").stdout.strip() == "arm64-v8a"
        assert shell("getprop ro.build.version.sdk").stdout.strip() == "32"
        shell("test -w /data/local/tmp")
        shell(f"test ! -e {TARGET} && test ! -L {TARGET}")
        # Reject an unexpected listener before even deploying the isolated test.
        for network_table in ("/proc/net/tcp", "/proc/net/tcp6"):
            text = shell("cat " + network_table).stdout
            for line in text.splitlines()[1:]:
                fields = line.split()
                assert not (len(fields) > 3 and fields[1].endswith(":FFFE") and fields[3] == "0A"), "Loopback test port already in use"
        report["before"] = snapshot()
        report["preflight"] = {"target_absent": True, "binary_sha256": EXPECTED_SHA,
                               "configuration_exactly_matches_public_preview": True,
                               "enrollment_configured": False, "token_configured": False,
                               "mqtt_endpoint": "127.0.0.1:65534"}
        save()
        print("Preflight passed; old logagent state: " + report["before"]["logagent_state"], flush=True)

        # mkdir without -p atomically refuses a directory created after preflight.
        shell(f"umask 077; mkdir -m 700 {TARGET}")
        report["board_write_started"] = True
        save()
        files = {"device-agent": binary, **{name: PREVIEW/name for name in (*expected_config, "log-sources.json")}}
        for name, path in files.items():
            adb(["push", str(path), TARGET + "/" + name])
        shell(f"chmod 0755 {TARGET}/device-agent")
        shell("chmod 0600 " + " ".join(TARGET + "/" + name for name in (*expected_config, "log-sources.json")))
        shell(f"mkdir -m 700 {TARGET}/empty-test-logs")
        remote_hashes = shell("sha256sum " + " ".join(TARGET + "/" + name for name in files)).stdout
        expected_hashes = {TARGET + "/" + name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in files.items()}
        assert {line.split()[1]: line.split()[0] for line in remote_hashes.splitlines()} == expected_hashes
        report["uploaded_files_sha256"] = expected_hashes
        report["permissions_before_start"] = shell(f"ls -ld {TARGET} {TARGET}/device-agent {TARGET}/device-agent.conf {TARGET}/device-agent.local.conf {TARGET}/log-sources.json {TARGET}/empty-test-logs").stdout.splitlines()
        print("Uploads and hashes verified; running isolated Agent for approximately 5 seconds", flush=True)
        launcher = f'''umask 077
cd {TARGET} || exit 90
timeout -v --preserve-status -s TERM -k 3 5 sh -c 'echo $$ > agent.pid; exec ./device-agent' > smoke-stdout.log 2>&1
result=$?
echo "$result" > smoke.exit-code
exit 0
'''
        report["launched"] = True
        save()
        started = time.monotonic()
        adb(["shell", "-T", "sh", "-s"], input=launcher, timeout=20)
        report["launch_wrapper_seconds"] = round(time.monotonic() - started, 3)
        pid = shell(f"cat {TARGET}/agent.pid").stdout.strip()
        assert pid.isdecimal(), "Invalid test PID"
        report["pid"] = int(pid)
        report["agent_exit_code"] = int(shell(f"cat {TARGET}/smoke.exit-code").stdout.strip())
        stdout = shell(f"cat {TARGET}/smoke-stdout.log").stdout
        agent_log = shell(f"cat {TARGET}/agent.log").stdout
        logcat = adb(["logcat", "-d", "--pid=" + pid, "-s", "DeviceAgent:I", "*:S"]).stdout
        for name, contents in (("smoke-stdout.log", stdout), ("smoke-agent.log", agent_log), ("smoke-logcat.log", logcat)):
            (OUTPUT / name).write_text(contents, encoding="utf-8")
        text = stdout + "\n" + agent_log + "\n" + logcat
        report["test_pid_still_present"] = shell(f"test -d /proc/{pid}", check=False).returncode == 0
        processes = shell("ps -A -o PID,NAME").stdout
        remaining = []
        for line in processes.splitlines()[1:]:
            parts = line.split()
            if len(parts) == 2 and parts[0].isdecimal() and "device-agent" in parts[1]:
                exe = shell(f"readlink /proc/{parts[0]}/exe", check=False).stdout.strip()
                if exe == TARGET + "/device-agent": remaining.append(int(parts[0]))
        report["remaining_test_processes"] = remaining
        report["no_test_token_directory"] = shell(f"test ! -e {TARGET}/state/tokens", check=False).returncode == 0
        report["runtime_permissions"] = shell(f"ls -ld {TARGET}/state {TARGET}/state/commands {TARGET}/state/registrations {TARGET}/work").stdout.splitlines()
        report["after"] = snapshot()
        report["original_service_and_identity_observations_unchanged"] = report["before"] == report["after"]
        markers = {"program_started": "START device-agent" in text,
                   "configuration_parsed": "environment=local cloud-wire=json" in text,
                   "isolated_source_loaded": "CONFIG loaded sources=1" in text and TARGET + "/empty-test-logs" in text,
                   "loopback_only_mqtt_attempt": "MQTT cloud connecting host=127.0.0.1 port=65534" in text,
                   "graceful_stop": "STOP device-agent" in text,
                   "no_enroll_or_token_use": not any(s in text for s in ("ENROLL requesting", "ENROLL succeeded", "AUTH loaded cached", "AUTH using configured"))}
        report["checks"] = markers
        report["stop_reason"] = "5-second deadline sent SIGTERM" if "timeout:" in text else "program exited before deadline; inspect log"
        report["passed"] = (all(markers.values()) and report["agent_exit_code"] == 0 and not remaining
                            and not report["test_pid_still_present"] and report["no_test_token_directory"]
                            and report["original_service_and_identity_observations_unchanged"])
        report["key_logs"] = [line for line in text.splitlines() if any(s in line for s in
                              ("CONFIG ", "START ", "SOURCE ", "MQTT cloud connecting", "timeout:", "STOP ", "FATAL "))]
        report["finished_utc"] = datetime.now(timezone.utc).isoformat()
        save()
        print(json.dumps({key: value for key, value in report.items() if key != "commands"}, indent=2, ensure_ascii=True))
        if not report["passed"]: raise RuntimeError("Smoke checks incomplete; inspect sanitized report")
    except Exception as exc:
        report["error"] = str(exc)
        try: report["after"] = snapshot()
        except Exception: report["after_snapshot_failed"] = True
        save()
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true", required=True, help="Run only after explicit user authorization")
    parser.parse_args()
    execute()
