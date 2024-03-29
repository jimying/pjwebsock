How to build
-------------------------------------------------------

1. Build the dependent library: pjproject

   ```bash
   # For we only need pjlib, so small build (without video)

   git clone https://github.com/pjsip/pjproject.git
   cd pjproject
   ./configure --prefix=$HOME/3rd/pjproject \
               --disable-video \
               --disable-libwebrtc \
               --disable-speex-codec --disable-speex-aec \
               --disable-libsrtp
   make dep
   make
   make install
   ```

2. Build with makefile (deprecated)

   ```bash
   # Set pkg-config search path
   export PKG_CONFIG_PATH=$HOME/3rd/pjproject/lib/pkgconfig:$PKG_CONFIG_PATH

   # Build test
   make
   ```


3. Build with cmake

   ```bash
   # Set pkg-config search path
   export PKG_CONFIG_PATH=$HOME/3rd/pjproject/lib/pkgconfig:$PKG_CONFIG_PATH

   # cmake build
   mkdir build
   cd build
   cmake ../
   make
   make install
   ```

