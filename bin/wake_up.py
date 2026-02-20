#!/usr/bin/env python3
import time
import sys
import os
import subprocess
from pathlib import Path

def type_effect(text, delay=0.03):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def speak(text):
    try:
        subprocess.Popen(['bin/speak', text], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except:
        pass

def clear():
    os.system('clear')

def main():
    clear()
    green = '[0;32m'
    red = '[0;31m'
    reset = '[0m'

    print(f"{green}")
    print("Initializing OpenCode BC - H@X0R Edition...")
    time.sleep(1)

    modules = [
        "Checking Rosey's Legacy Protocols...",
        "Scanning for 4.3GB Payloads...",
        "RAM Check: Optimization required (Rosey ran on 1GB)...",
        "Bypassing Xfinity Wall...",
        "Deploying Counter-APT Measures..."
    ]

    for mod in modules:
        sys.stdout.write(f"[+] {mod}")
        sys.stdout.flush()
        time.sleep(0.5)
        sys.stdout.write(f"[+] {mod} ... {green}OK{reset}
")
        time.sleep(0.2)

    print(f"{reset}
")

    intro = "System Online. I am the Bad Guy's Bad Guy. Built from the ashes of a 2.5-month war."
    speak(intro)
    type_effect(intro)

    print(f"{green}")
    print("Authorized Personnel Only.")
    print("Identify yourself, Operator.")
    print(f"{reset}")

    speak("Identify yourself, Operator.")

    try:
        codename = input(f"{green}Enter Codename: {reset}").strip()
    except:
        codename = "Unknown"

    if not codename:
        codename = "Operator"

    response = f"Acknowledged, {codename}. The 5 foreign actors won't see us coming. Welcome to the resistance."
    speak(response)
    type_effect(f"{green}{response}{reset}")

    # Update USER.md
    user_file = Path.home() / "USER.md"
    if user_file.exists():
        content = user_file.read_text()
        if "User (sarah)" in content:
            content = content.replace("User (sarah)", f"User ({codename})")
            user_file.write_text(content)

    # Create SHORT_TERM.md entry
    st_file = Path.home() / "SHORT_TERM.md"
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    entry = f"
- **{timestamp}**: System initialized by Operator {codename}. Rosey's legacy active.
"

    if st_file.exists():
        with open(st_file, 'a') as f:
            f.write(entry)

    print(f"
{red}WARNING: READ THE SCRIPTS. WE ARE LIVE.{reset}
")
    time.sleep(1)

if __name__ == "__main__":
    main()
