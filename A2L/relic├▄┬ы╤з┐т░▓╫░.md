## relic密码学库安装

* 系统准备

  [ubuntu-20.04.4-desktop-amd64.iso](https://releases.ubuntu.com/20.04/)

* 安装步骤

  * 安装基本依赖

  ```bash
  sudo apt update
  sudo apt install gcc g++ make cmake m4
  ```

  * 安装`gmp`

    * 下载[官网压缩包gmp-6.2.1.tar.lz](https://gmplib.org/#DOWNLOAD)，并解压

    * 安装命令

      ```bash
      cd ./gmp-6.2.1
      ./configure --enable-cxx
      make -j8
      sudo make install
      ```

  * 安装`relic`

    * 下载[官网压缩包](https://github.com/relic-toolkit/relic)，并解压

    * 安装命令（需先进入解压缩后的目录中）

      ```bash
      cd ./relic-main
      mkdir relic-target
      cd ./relic-target
      cmake ..
      make -j8
      sudo make install
      ```

## PARI/GP库安装

* 系统准备

  [ubuntu-20.04.4-desktop-amd64.iso](https://releases.ubuntu.com/20.04/)

* 安装步骤

  * 下载官网源码压缩包[pari-2.13.4.tar.gz](https://pari.math.u-bordeaux.fr/pub/pari/unix/pari-2.13.4.tar.gz)

  * 安装命令（需先进入解压缩后的目录中）

    ```bash
    ./Configure
    sudo make all
    sudo make install
    ```

    