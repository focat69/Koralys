<p align="center">
  <img src="./banner.png" alt="Koralys Disassembler Banner" width="500px" height=auto>
</p>

<h1 align="center">Koralys Disassembler & Decompiler</h1>

This project is a result of countless hours of hard work and development. We ask that you do not claim this project as your own, and give credit where it is due.  

> Join our [Discord Server](https://discord.gg/Thx7KGyM2Q) for updates, support, and more!

> **Note:** This project is licensed under the GNU General Public License v3.0.

I've included an example v5 bytecode file that you can use for testing this project out.

## Written by:
- **focat**
  - Discord: @focat (676960182621962271)
  - GitHub: [focat69](https://github.com/focat69)
- **Jiface**
  - Discord: @_jifacepellyfreckles (1233718214714724385)
  - GitHub: [ssynical](https://github.com/ssynical)

## Debug Mode

Turning on the `DEBUG` flag will slow down the decompilation process significantly.
- **Performance Impact:** 0.000406s -> 0.002075s, around 5x slower

The `DEBUG` flag is meant for development purposes only. Turn off before using in production.

## Version Support

> **Note:** There is no V6 support in this version! To get access, become a beta tester.

## Issues

- Makes everything a proto even if it isn't
- Does not show jump targets (e.g., if code has `goto [5]` but only has 3 instructions, it doesn't show `::5::` and its dism)
- Decompile is broken/really bad/unfinished
- No type checking
- Does not handle variables kindly
- No v6 support (not an issue, just not added to this version lol)

Please contribute and fix these bugs and more that you may find (except v6 support, we got dat)
