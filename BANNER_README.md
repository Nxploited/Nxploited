# Nxploited Banner Tool

A professional command-line tool that displays the Nxploited ASCII art banner with color animations.

## Features

- **ASCII Art Banner**: Displays the Nxploited banner in dark green
- **Animated Text**: Shows "Nxploited" text cycling through terminal colors (white, magenta, cyan, green, yellow, red)
- **English Only**: All output is in English with professional, classic styling
- **No Dependencies**: Uses only Python standard library

## Requirements

- Python 3.6 or higher
- Terminal with ANSI color support

## Usage

Run the script directly:

```bash
python3 nxploited.py
```

Or make it executable and run:

```bash
chmod +x nxploited.py
./nxploited.py
```

## Output

The tool will:
1. Clear the screen
2. Display the ASCII art banner in dark green
3. Animate the "Nxploited" text through multiple color cycles
4. End with the text displayed in magenta

## Features Details

### Banner
The banner is displayed in a fixed dark green color and shows the Nxploited logo in ASCII art format.

### Animation
The "Nxploited" text below the banner animates by cycling through 6 colors:
- White
- Magenta
- Cyan
- Green
- Yellow
- Red

The animation runs for 3 complete cycles (18 color changes total) before stopping and displaying the final text in magenta.

## Technical Details

- Uses ANSI escape codes for colors and cursor control
- Animation speed: 0.3 seconds per color change
- Terminal screen is cleared before displaying the banner
- Carriage return (`\r`) is used for smooth text color transitions

## Author

Nxploited - Offensive Security Researcher | Exploit Developer | CVE Hunter
