# UOFlow

UOFlow is a UI modification for the **Ultima Online Enhanced Client** focused on expanding the game's built in macro and automation functionality. The goal is to make complex actions possible directly within the client through a visual programming interface written in Lua.

## Features

- Custom visual programming interface for building in-game logic
- Extensible action and trigger system written in Lua
- Support for user made macros and enhanced context menus
- Modular design allowing additional UI components to be added over time

### Sample Actions

- **Print Message** – outputs text to the debug console, chat window or overhead depending on user selection

## Repository Layout

- `UOFlow/` – Core mod files, Lua sources and interface XML definitions
- `UOFlow/Source/` – Main Lua scripts for UI windows, macros and the visual programming system
- `UOFlow/Source/UOFlow/` – Implementation of the visual programming interface
- `Anarchy` – Example configuration XML shipped with the mod

## Usage

These files are intended to be placed inside the `UserInterface` folder of your Ultima Online installation. After copying, start the Enhanced Client and select the *UOFlow* UI in the options menu.

Development of this project is Lua based and does not currently include an automated build system. Most files can be edited directly and reloaded by restarting the client.

## Contributing

Pull requests are welcome. See the TODO list for planned improvements. When adding new features make sure Lua scripts remain syntax compatible with Lua 5.1 which the client uses.


