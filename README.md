## drootkit
drootkit可以用来检测以内核模块的形式呈现的篡改系统调用表的rootkit攻击，适用于arm64架构的内核版本5.10+的Linux系统。具体功能为：
1. 检测当前系统的系统调用是否被篡改，如果被篡改，则在终端上抛出如下警告信息：
![image](https://user-images.githubusercontent.com/112916389/235735351-c8159d73-76c0-4e35-87c4-0648e87c72a0.png)
2. 如有系统调用被篡改，则将其恢复到正确的状态
3. 定位并卸载恶意内核模块

## Code structure
![image](https://user-images.githubusercontent.com/112916389/235739325-b8936dc9-9674-4351-94e6-cb10b493350d.png)

## Uasge
1. git clone --recursive 
1. 将drootkit.c和drootkit.bpf.c以及相关的文件拷贝到libbpf-bootstrap/examples/c下
2. 将libbpf-bootstrap/examples/c中的Mackfile替换为本仓库中的Makefile
3. 在libbpf-bootstrap/examples/c中使用make drootkit ARCH=arm64命令进行编译
4. 使用 sudo ./drootkit运行
