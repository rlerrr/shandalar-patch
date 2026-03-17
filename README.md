# Shandalar patcher

An unofficial patcher for the 1997 video game [Magic: the Gathering](https://en.wikipedia.org/wiki/Magic:_The_Gathering_(1997_video_game)) by MicroProse.  With the goal of making the game playable on modern Windows without changing gameplay meaningfully.  This is **not** related to other patches which add cards or functionality and is not compatible with them.

## Included fixes

* Disables broken DRM functions that rely on a Windows 95/98 ProductId in the registry.
* Fixes buffer overflows in card rendering when running at resolutions over 1280x1024 (tested up to 4k resolution).
* Fixes invalid Windows API params that are no longer silently ignored.
* Fixes the framerate limiter in `shandalar.exe`.
* Cuts AI thinking time by 90% (still overkill on modern CPUs).

### Prerequisites

An original unmodifed copy of MicroProse's [Magic:The Gathering](https://en.wikipedia.org/wiki/Magic:_The_Gathering_(1997_video_game)) "Duels of the Planeswalkers" version.

The final "Manalink" patch released by MicroProse, version 1.3.  Usually installed via a patcher named `mtg_13us.exe`.  Or even easier: [this](https://archive.org/details/score54cd) archive contains a `mtg_13us.zip` with the same binaries. (See `specs.json` for expected MD5 hashes)

### Usage
1. Create an `in` subfolder and extract or copy the unpatched binaries to it.
2. Run `python patch.py`
3. Copy the patched binaries from the newly created `patched` folder to the original install location.

### Known issues

* `shandalar.exe` and `facemaker.exe` freak out if Windows scaling isn't 100% and will crash if they can't set the resolution to 1024x768.
* `shandalar.exe` has several text labels that aren't drawn, e.g.
    * Lost this Card
    * Buy for X gold Y/N
    * Begin a Quest (resolves when hovered)