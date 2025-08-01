# PLaZA: Passwordless Lattice-based Zero Knowledge Web Application

## Setup for Windows

### Prerequisites
- **CMake**: Install from https://cmake.org/download/
    - Add to environment variables PATH (eg. C:\Program Files\CMake\bin). Test with `cmake --version`.
- **Visual Studio**: Install Community 2022 with and in the installer select "Desktop development with C++" workload (includes MSVC compiler).
- Donwload Git
- Download and install OpenSSL from https://slproweb.com/products/Win32OpenSSL.html
    - Add to PATH. (optional)
- **Admin Access**: Some steps may need admin rights.

### Steps

- Create a virtual environment and install the required dependencies using "pip install -r requirements.txt" in order to run the python application. The requirements file includes dynamic and remote packages, so ensure Git is installed. Python 3.8+ is required.
- Build liboqs (C Library):
- git clone --recursive https://github.com/open-quantum-safe/liboqs.git
- cd liboqs
- mkdir build && cd build
- cmake -G "Visual Studio 17 2022" -A x64 -DCMAKE_INSTALL_PREFIX="C:\liboqs" -DOPENSSL_DIR="C:\Program Files\OpenSSL-Win64" ..
  - For Visual Studio 2019, replace with "Visual Studio 16 2019"
- Run the application "Developer command prompt for VS 2022" from the Start Menu.
- **Ensure the current directory is inside the "liboqs" folder before following the next steps.**
- In the now opened developer cmd, run the following commands for Build and install (run inside the liboqs folder):
  - msbuild ALL_BUILD.vcxproj /p:Configuration=Release
  - msbuild INSTALL.vcxproj /p:Configuration=Release
- Add "..\..\liboqs\bin" to your system PATH under System "Environment Variables"
- In the parent directory that contains "liboqs", run the following command so that there are now two folders "liboqs" and "liboqs-python":
  - git clone https://github.com/open-quantum-safe/liboqs-python.git
  - cd liboqs-python
  - pip install .
- Install Other dependencies
  - pip install flask, flask_session
  
  - Now run the plaza-app.py
      - Allow whatever automatic installation appears after running our "plaza-app.py"
  - **Installation is now complete.**

(For further help, look at the original liboqs' instructions for more context: https://github.com/open-quantum-safe/liboqs-python)
