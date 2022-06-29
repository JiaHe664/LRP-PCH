# A2L
Anonymous Atomic Locks for Scalability in Payment Channel Hubs

## 依赖

- [CMake](https://cmake.org/download/) >= 3.23.0
- [GMP](https://gmplib.org/) >= 6.2.1
- [RELIC](https://github.com/relic-toolkit/relic) (configured and built with `-DARITH=gmp`)
- [PARI/GP](https://pari.math.u-bordeaux.fr/) >= 2.13.4

## 运行步骤

* 进入目录`A2L\src\build`

* 运行命令

  ```bash
  cmake ..
  make
  ./performance
  ```

## 参考文献

[1] Erkan Tairi, Pedro-Moreno Sanchez, and Matteo Maffei, "[A2L: Anonymous Atomic Locks for Scalability and Interoperability in Payment Channel Hubs](https://eprint.iacr.org/2019/589)".

## 致谢

本项目大部分代码均来自[github：etairi/A2L](https://github.com/etairi/A2L)，感谢他们。