# Introduction

An example which implements sllurp through a graphical unit interface.

Available feature:
- inventory

Tag memory read/write are not available.


# Getting started

**Install requirements**
```
pip install pyqtgraph pyqt5
```

**Run GUI**
```
python3 main.py
```

# Generate single-file exe

**Install requirements**
```
pip install pyinstaller
```

Install sllurp because the `import initExample` in main.py does not work with pyinstaller
```
cd ../../.. # move to the root of sllurp repository
pip install .
```

**Linux**  
``` bash
PyInstaller --noconfirm --log-level=INFO \
--onefile \
--windowed \
--hidden-import='pkg_resources.py2_warn' \
main.py

```

**Windows**  

``` bash
PyInstaller --noconfirm --log-level=INFO ^
    --onefile ^
    --paths="C:\Users\root\AppData\Roaming\Python\Python37\site-packages\PyQt5\Qt\bin" ^
    --hidden-import="pkg_resources.py2_warn" ^
    main.py
```
Note: update the `--paths` option to set the Qt path according to your setup.
