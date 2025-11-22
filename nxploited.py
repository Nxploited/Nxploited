#!/usr/bin/env python3
"""
Nxploited Banner Display Tool
A professional CLI tool that displays the Nxploited banner with animations.
"""

import time


class Colors:
    """ANSI color codes for terminal output."""
    DARK_GREEN = '\033[32m'
    WHITE = '\033[97m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    RESET = '\033[0m'


def clear_screen():
    """Clear the terminal screen."""
    print('\033[2J\033[H', end='')


def display_banner():
    """Display the ASCII art banner in dark green."""
    # Using individual print statements to avoid string literal issues with backticks
    lines = [
        "           _  _             _ __     _               _      _                 _   ",
        "    o O O | \\| |   __ __   | '_ \\   | |     ___     (_)    | |_     ___    __| |  ",
        "   o      | .` |   \\ \\ /   | .__/   | |    / _ \\    | |    |  _|   / -_)  / _` |  ",
        "  TS__[O] |_\\_|   /_\\_\\   |_|__   _|_|_   \\___/   _|_|_   _\\__|   \\___|  \\__,_|  ",
        " {======|_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"| ",
        "./o--000'\"`-0-0-'\"`-0-0-'\"`-0-0-'\"`-0-0-'\"`-0-0-'\"`-0-0-'\"`-0-0-'\"`-0-0-'\"`-0-0-' "
    ]
    
    print(Colors.DARK_GREEN, end='')
    for line in lines:
        print(line)
    print(Colors.RESET, end='')


def animate_nxploited_text(cycles=3):
    """
    Display 'Nxploited' text with color animation.
    
    Args:
        cycles: Number of times to cycle through all colors
    """
    text = "Nxploited"
    colors = [
        Colors.WHITE,
        Colors.MAGENTA,
        Colors.CYAN,
        Colors.GREEN,
        Colors.YELLOW,
        Colors.RED
    ]
    
    # Animate through colors for specified cycles
    for cycle in range(cycles):
        for color in colors:
            # Move cursor to beginning of line and print colored text
            print(f'\r{color}{text}{Colors.RESET}', end='', flush=True)
            time.sleep(0.3)
    
    # Final display in magenta
    print(f'\r{Colors.MAGENTA}{text}{Colors.RESET}')


def main():
    """Main function to display the banner and animated text."""
    clear_screen()
    display_banner()
    print()  # Add blank line between banner and animated text
    animate_nxploited_text()
    print()  # Add blank line after animation


if __name__ == "__main__":
    main()
