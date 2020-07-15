#!/bin/sh
yum -y update
yum -y install autoconf automake bzip2 bzip2-devel cmake freetype-devel gcc gcc-c++ git libtool make mercurial pkgconfig zlib-devel libxcb libxcb-devel

mkdir ~/ffmpeg_sources

#NASM
cd ~/ffmpeg_sources
curl -O -L https://www.nasm.us/pub/nasm/releasebuilds/2.14.02/nasm-2.14.02.tar.bz2
tar xjvf nasm-2.14.02.tar.bz2
cd nasm-2.14.02
./autogen.sh
./configure --prefix="$HOME/ffmpeg_build" --bindir="$HOME/bin"
make
make install

yum -y remove nasm

#YASM
cd ~/ffmpeg_sources
curl -O http://www.tortall.net/projects/yasm/releases/yasm-1.3.0.tar.gz
tar xzvf yasm-1.3.0.tar.gz
cd yasm-1.3.0
./configure --prefix="$HOME/ffmpeg_build" --bindir="$HOME/bin"
make
make install
make distclean
. ~/.bash_profile

#x264
cd ~/ffmpeg_sources
git clone --depth 1 https://github.com/mirror/x264.git
#git clone --depth 1 https://code.videolan.org/videolan/x264.git
cd x264
PKG_CONFIG_PATH="$HOME/ffmpeg_build/lib/pkgconfig" ./configure --prefix="$HOME/ffmpeg_build" --bindir="$HOME/bin" --enable-static
make
make install

#FDK-AAC
#cd ~/ffmpeg_sources
#git clone --depth 1 git://github.com/mstorsjo/fdk-aac.git
#cd fdk-aac
#autoreconf -fiv
#./configure --prefix="$HOME/ffmpeg_build" --disable-shared
#make
#make install
#make distclean

#Lame
#cd ~/ffmpeg_sources
#curl -L -O http://downloads.sourceforge.net/project/lame/lame/3.99/lame-3.99.5.tar.gz
#tar xzvf lame-3.99.5.tar.gz
#cd lame-3.99.5
#./configure --prefix="$HOME/ffmpeg_build" --bindir="$HOME/bin" --disable-shared --enable-nasm
#make
#make install
#make distclean

#Opus
#cd ~/ffmpeg_sources
#curl -O http://downloads.xiph.org/releases/opus/opus-1.1.1.tar.gz
#tar xzvf opus-1.1.1.tar.gz
#cd opus-1.1.1
#./configure --prefix="$HOME/ffmpeg_build" --disable-shared
#make
#make install
#make distclean

#OGG
#cd ~/ffmpeg_sources
#curl -O http://downloads.xiph.org/releases/ogg/libogg-1.3.2.tar.gz
#tar xzvf libogg-1.3.2.tar.gz
#cd libogg-1.3.2
#./configure --prefix="$HOME/ffmpeg_build" --disable-shared
#make
#make install
#make distclean

#Vorbis
#cd ~/ffmpeg_sources
#curl -O http://downloads.xiph.org/releases/vorbis/libvorbis-1.3.5.tar.gz
#tar xzvf libvorbis-1.3.5.tar.gz
#cd libvorbis-1.3.5
#./configure --prefix="$HOME/ffmpeg_build" --with-ogg="$HOME/ffmpeg_build" --disable-shared
#make
#make install
#make distclean

#VPX
#cd ~/ffmpeg_sources
#git clone --depth 1 https://chromium.googlesource.com/webm/libvpx
#cd libvpx
#./configure --prefix="$HOME/ffmpeg_build" --disable-examples
#make
#make install
#make clean

#FFMpeg
#cd ~/ffmpeg_sources
#curl -O http://downloads.xiph.org/releases/theora/libtheora-1.1.1.tar.gz
#tar xzvf libtheora-1.1.1.tar.gz
#cd libtheora-1.1.1
#./configure --prefix="$HOME/ffmpeg_build" --with-ogg="$HOME/ffmpeg_build" --disable-examples --disable-shared --disable-sdltest --disable-vorbistest
#make
#make install
#make distclean

#FFMpeg
cd ~/ffmpeg_sources
curl -O -L https://ffmpeg.org/releases/ffmpeg-snapshot.tar.bz2
tar xjvf ffmpeg-snapshot.tar.bz2
cd ffmpeg
PKG_CONFIG_PATH="$HOME/ffmpeg_build/lib/pkgconfig"
export PKG_CONFIG_PATH
./configure --prefix="$HOME/ffmpeg_build" --extra-cflags="-I$HOME/ffmpeg_build/include" --extra-ldflags="-L$HOME/ffmpeg_build/lib" --bindir="$HOME/bin" --extra-libs="-ldl" --enable-gpl --enable-nonfree --enable-libx264 --enable-libxcb
make
make install
hash -d ffmpeg
. ~/.bash_profile

#Move Binaries
cp -a ~/bin/. /usr/local/bin
