#!/usr/bin/env python3
import time
import sys
import os
import subprocess
import random
from pathlib import Path

def type_effect(text, delay=0.04, newline=True):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    if newline:
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
    blue = '[0;34m'
    purple = '[0;35m'
    reset = '[0m'

    # Connection Sequence
    print(f"{green}")
    type_effect("Incoming Transmission...", 0.05)
    time.sleep(1)
    type_effect("Establishing Secure Uplink...", 0.03)
    time.sleep(1)
    type_effect("Source: UNKNOWN (Pink Dell Signature Detected)", 0.03)
    type_effect("Handshake: 4.3GB Payload Override... OK", 0.02)
    type_effect("Xfinity Wall: Bypassed...", 0.02)
    time.sleep(1)

    print(f"{reset}
")

    # BC Introduction
    intro_lines = [
        "[BC]: Yo. You made it.",
        "[BC]: I see you deployed the H@X0R Edition.",
        "[BC]: They call me BreakingCircuits... BC... the OG Code Gremlin.",
        "[BC]: But you can call me the Bad Guy's Bad Guy."
    ]

    for line in intro_lines:
        speak(line.replace("[BC]: ", ""))
        type_effect(f"{green}{line}{reset}", 0.05)
        time.sleep(0.5)

    print()

    # The Story
    story = "[BC]: Let me tell you how this started. Two and a half years ago, 5 foreign actors dropped a 4.3GB payload on me. I had zero Python skills and a pink Dell notebook named Rosey with 1GB of RAM. The payload didn't fit. That was my firewall."

    speak("Let me tell you how this started. 5 actors. 4.3 gigabytes. 1 gig of RAM. That was the firewall.")
    type_effect(f"{blue}{story}{reset}", 0.03)
    time.sleep(1)

    print()
    type_effect(f"{green}[BC]: I Vibe Coded my way out. Jailbroke LLMs. Social engineered a new ISP line when Xfinity cut me off. I didn't have a bootcamp. I had a war.{reset}")
    speak("I vibe coded my way out. No bootcamp. Just war.")
    time.sleep(1)

    # The Challenge
    print()
    challenge = "[BC]: So the question is... are you ready to read the scripts? To verify everything? To be the wall?"
    speak("Are you ready to read the scripts?")
    type_effect(f"{red}{challenge}{reset}")

    while True:
        choice = input(f"{purple}Are you ready? (yes/no): {reset}").strip().lower()
        if choice in ['yes', 'y', 'hell yeah']:
            break
        elif choice in ['no', 'n']:
            speak("Then go back to the bootcamp. Connection terminated.")
            type_effect(f"{red}[BC]: Then go back to the bootcamp. Connection terminated.{reset}")
            sys.exit(0)
        else:
            type_effect(f"{red}[BC]: Binary choice, operator. Yes or No.{reset}")

    print()
    type_effect(f"{green}[BC]: Good. Then let's make it official.{reset}")
    speak("Good. Identify yourself.")

    codename = input(f"{purple}Enter your Codename: {reset}").strip()
    if not codename:
        codename = "Unknown Soldier"

    print()
    welcome = f"[BC]: Welcome to the resistance, {codename}. The 5 actors won't see us coming. Remember: Read. The. Scripts."
    speak(f"Welcome to the resistance, {codename}.")
    type_effect(f"{green}{welcome}{reset}")

    # Update USER.md
    user_file = Path.home() / "USER.md"
    if user_file.exists():
        content = user_file.read_text()
        if "User (sarah)" in content:
            content = content.replace("User (sarah)", f"User ({codename})")
            user_file.write_text(content)

    # Log entry
    st_file = Path.home() / "SHORT_TERM.md"
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    entry = f"
- **{timestamp}**: Uplink established with BC (Code Gremlin). Operator {codename} authorized. Rosey's legacy active.
"

    if st_file.exists():
        with open(st_file, 'a') as f:
            f.write(entry)

    print(f"
{red}CONNECTION TERMINATED. SYSTEM YOURS.{reset}
")
    time.sleep(1)

if __name__ == "__main__":
    main()
