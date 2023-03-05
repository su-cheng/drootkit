# drootkit

1. 将drootkit.c和drootkit.bpf.c以及相关的文件拷贝到libbpf-bootstrap/examples/c下
2. 将libbpf-bootstrap/examples/c中的Mackfile替换为本仓库中的Makefile
3. 在libbpf-bootstrap/examples/c中使用make drootkit ARCH=arm64命令进行编译
4. 使用 sudo ./drootkit运行
