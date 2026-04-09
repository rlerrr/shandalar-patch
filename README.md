# Shandalar patcher

A series of patches for the 1997 video game [Magic: the Gathering](https://en.wikipedia.org/wiki/Magic:_The_Gathering_(1997_video_game)) by MicroProse.  Allows the game to run on Windows 10/11 without changing gameplay meaningfully.  This is **not** related to other patches which add cards or functionality and is not compatible with them.  The result is still pretty rough and has several annoying issues not present when running on Windows 95/98.

## Included fixes

* Disables broken DRM functions that rely on a Windows 95/98 ProductId in the registry.
* Fixes various crashes at resolutions over 1024x768 (tested up to 4k resolution).  Still recommended to run at 1024x768.
* Fixes invalid Windows API params that are no longer silently ignored.
* Fixes the framerate limiter.
* Fixes text rendering issues.
* Cuts AI thinking time by 90% (still overkill on modern CPUs).

### Prerequisites

An original unmodifed copy of MicroProse's [Magic:The Gathering](https://en.wikipedia.org/wiki/Magic:_The_Gathering_(1997_video_game)) "Duels of the Planeswalkers" version.

The final "Manalink" patch released by MicroProse, version 1.3.  Usually installed via a patcher named `mtg_13us.exe`.  Or even easier: [this](https://archive.org/details/score54cd) archive contains a `mtg_13us.zip` with the same binaries. (See `specs.json` for expected MD5 hashes)

### Usage
1. Create an `in` subfolder and extract or copy the unpatched binaries to it.
2. Run `python patch.py`
3. Copy the patched binaries from the newly created `patched` folder to the original install location.

### Known issues

* While it no longer instantly crashes above 1024x768, most of the game will be windowed and a bit glitchier.
* Buying food repeats WAY too fast. It's almost impossible to buy 1 stack.