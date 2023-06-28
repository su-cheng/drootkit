## drootkit
drootkit可以用来检测以内核模块的形式呈现的篡改系统调用表的rootkit攻击，适用于arm64架构的内核版本5.10+的Linux系统。具体功能为：
1. 检测当前系统的系统调用是否被篡改，如果被篡改，则在终端上抛出如下警告信息：
![image](https://user-images.githubusercontent.com/112916389/235735351-c8159d73-76c0-4e35-87c4-0648e87c72a0.png)
2. 如有系统调用被篡改，则将其恢复到正确的状态
3. 定位并卸载恶意内核模块

## Code structure
![image](https://user-images.githubusercontent.com/112916389/235739325-b8936dc9-9674-4351-94e6-cb10b493350d.png)

## Uasge
#### 部署drootkit
1. 克隆本仓库到本地，注意更新子仓库 `git clone --recursive https://github.com/su-cheng/drootkit.git`
2. 将主体代码部分的文件拷贝到`libbpf-bootstrap/examples/c`下( 替换原本的`Makefile`)
3. 进入`re_syscall`目录，使用`make`命令编译得到`re_syscall.ko`，并将`re_syscall.ko`拷贝到`libbpf-bootstrap/examples/c`下
4. 在`libbpf-bootstrap/examples/c`中使用`make drootkit ARCH=arm64`命令编译drootkit程序
5. 使用 `sudo ./drootkit`运行
> 可以使用`cp ./drootkit.sh /usr/bin/drootkit`将drootkit.sh包装成drootkit命令
#### 测试drootkit
> 建议在虚拟机上做测试
1. 在一个终端中使用 `sudo ./drootkit`使drootkit程序运行在后台
2. 进入`syscall_hook`目录，使用`make`命令编译得到`syscall_hook.ko`
3. 查看/proc/kallsyms文件，得到sys_call_table和init_mm的地址
4. 运行`insmod syscall_hook.ko sys_call_table=xxxxxxxx init_mm=xxxxxxxxxx syscall_nr=xx`载入恶意内核模块，其需要三个参数，sys_call_table和init_mm通过第3步得到，syscall_nr为希望篡改的系统调用的系统调用号
5. 可以通过查看`sudo dmesg`信息来判断是否入侵成功
