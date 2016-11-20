# Mobile Code Checks

Static Analysis Checks for Android and iOS codebases


## iOS

This has now been embedded into [Needle](https://github.com/mwrlabs/needle):

```
use static/code_checks
```


## Android

`android-checks.py` can run the checks against a codebase, or it can compute the diff between 2 versions of the same codebase and run the checks only against the modified files. 
It will output filenames and number of the offending lines.
It will also create a `.debug` logfile with a copy of the output.

Usage:

* Run against a folder: `python android-checks.py -f /full/path/of/folder/`
* Run a diff:           `python android-checks.py -d1 /full/path/of/folder_old/ -d2 /full/path/of/folder_new/`

**Remember to use absolute paths**
