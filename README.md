<p align="center">
  <img src="./banner.png" alt="Koralys Disassembler Banner" width="500px" height=auto>
</p>

<h1 align="center">Koralys Disassembler & Decompiler</h1>

This project is a result of countless hours of hard work and development. We ask that you do not claim this project as your own, and give credit where it is due.  

> Join our [Discord Server](https://discord.gg/Thx7KGyM2Q) for updates, support, and more!

> **Note:** This project is licensed under the GNU General Public License v3.0.

If you'd like to compile your script, please refer to the `/compile` directory.

## Written by:
- **focat**
  - Discord: @focat (676960182621962271)
  - GitHub: [focat69](https://github.com/focat69)
- **Jiface**
  - Discord: @_jifacepellyfreckles (1233718214714724385)
  - GitHub: [ssynical](https://github.com/ssynical)
- **DataModell**
  - Discord: @datamodel (773207810120089600)
  - GitHub: [DataM0del](https://github.com/DataM0del)
- **Desiderium / Lxnny**
  - Discord: @000desiderium (1122940719531839638)
  - GitHub: [lxnnydev](https://github.com/lxnnydev)

## Debug Mode

Turning on the `DEBUG` flag will slow down the decompilation process significantly.
- **Performance Impact:** 0.000406s -> 0.002075s, around 5x slower

The `DEBUG` flag is meant for development purposes only. Turn off before using in production.

## Issues

- Makes everything a proto even if it isn't
  
- ~~Does not show jump targets (e.g., if code has `goto [5]` but only has 3 instructions, it doesn't show `::5::` and its dism)~~ (Fixed, but not implemented?)
-> May cause some complications though

- Decompile is broken/really bad/unfinished
- No type checking
- Does not handle variables kindly

Please contribute and fix these bugs and more that you may find
