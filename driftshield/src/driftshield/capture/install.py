"""Text for running ``driftshield capture watch`` every minute. Prints only."""

from __future__ import annotations

import sys
from pathlib import Path
from xml.sax.saxutils import escape

LABEL = "ai.driftshield.capture"


def launchd_plist(python: str, log_dir: Path, interval: int = 60) -> str:
    args = "".join(
        f"\t\t<string>{escape(part)}</string>\n"
        for part in (python, "-m", "driftshield.cli.main", "capture", "watch")
    )
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<key>Label</key>
\t<string>{LABEL}</string>
\t<key>ProgramArguments</key>
\t<array>
{args}\t</array>
\t<key>RunAtLoad</key>
\t<true/>
\t<key>StartInterval</key>
\t<integer>{interval}</integer>
\t<key>StandardOutPath</key>
\t<string>{escape(str(log_dir / "watch.log"))}</string>
\t<key>StandardErrorPath</key>
\t<string>{escape(str(log_dir / "watch.err"))}</string>
</dict>
</plist>
"""


def systemd_units(python: str, interval: int = 60) -> str:
    return f"""# ~/.config/systemd/user/driftshield-capture.service
[Unit]
Description=DriftShield capture watch tick

[Service]
Type=oneshot
ExecStart={python} -m driftshield.cli.main capture watch

# ~/.config/systemd/user/driftshield-capture.timer
[Unit]
Description=Run the DriftShield capture watch tick every {interval} seconds

[Timer]
OnBootSec={interval}
OnUnitActiveSec={interval}

[Install]
WantedBy=timers.target

# then: systemctl --user daemon-reload && systemctl --user enable --now driftshield-capture.timer
"""


def install_text(
    *, systemd: bool, log_dir: Path, python: str | None = None, interval: int = 60
) -> str:
    interpreter = python or sys.executable
    if systemd:
        return systemd_units(interpreter, interval)
    plist = launchd_plist(interpreter, log_dir, interval)
    target = f"~/Library/LaunchAgents/{LABEL}.plist"
    return (
        f"# Save as {target}, then: launchctl load {target}\n"
        "# Run `driftshield capture dry-run` first, and only load it once capture is on.\n" + plist
    )


__all__ = ["LABEL", "install_text", "launchd_plist", "systemd_units"]
