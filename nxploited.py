#!/usr/bin/env python3
"""
Nxploited - Offensive Security Tool
Author: Khaled Al Enazi
"""

def animated_banner():
    """Display the Nxploited banner"""
    banner_lines = [
        "",
        "           _  _             _ __     _               _      _                 _   ",
        "    o O O | \\| |   __ __   | '_ \\   | |     ___     (_)    | |_     ___    __| |  ",
        "   o      | .` |   \\ \\ /   | .__/   | |    / _ \\    | |    |  _|   / -_)  / _` |  ",
        "  TS__[O] |_\\_|   /_\\_\\   |_|__   _|_|_   \\___/   _|_|_   _\\__|   \\___|  \\__,_|  ",
        " {======|_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"| ",
        "./o--000'\"`-0-0-'\"`-0-0-'\"`-0-0-'\"`-0-0-'\"`-0-0-'\"`-0-0-'\"`-0-0-'\"`-0-0-'\"`-0-0-' ",
        ""
    ]
    print("\n".join(banner_lines))


def main():
    """Main function"""
    animated_banner()
    print("\n[*] Nxploited - Offensive Security Tool")
    print("[*] Author: Khaled Al Enazi")
    print("[*] Telegram: @KNxploited\n")


if __name__ == "__main__":
    main()
