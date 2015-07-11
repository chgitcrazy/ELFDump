#include <sys/ptrace.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <malloc.h>
#include <stdlib.h>
#include </usr/include/elf.h>
#include <sys/user.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>


#define MAX_SIZE 2000000

//elf header
static Elf32_Ehdr elf_h;
//elf section header table
static Elf32_Shdr elf_s;
//elf program header table
static Elf32_Phdr elf_p;
//elf symbol table
static Elf32_Sym  elf_dynsym;
//elf dynamic segment
static Elf32_Dyn elf_dyn;
//elf rel segment
static Elf32_Rel elf_rel;
//elf rela segment
static Elf32_Rela elf_rela;

int OpenElf(char *filename)
{
     int fd;
     //open the file with read-only mode
     fd = open(filename,O_RDONLY);
     if(fd == -1)
     {
       printf("Open %s Error!\n",filename);
     }
     return fd;
}

void CloseElf(int fd)
{
     close(fd);
}
     
int main(int argc , char **argv)
{
    int fd;
    int num = 0;
    char str[MAX_SIZE]; 
    memset(str,0,MAX_SIZE);
    fd = OpenElf(argv[1]);
    num = read(fd,str,MAX_SIZE);

    if((str[0] == 0x7f) && (str[1] == 'E') && (str[2] == 'L') && (str[3] == 'F'))
     {
        /*
         *read the elf header information
        */
       elf_h.e_entry = *((Elf32_Addr *)&str[24]);
       printf("entry point address:0x%x\n",elf_h.e_entry);
       elf_h.e_phoff = *((Elf32_Off *)&str[28]);
       printf("program header table file offset:%d\n",elf_h.e_phoff);
       elf_h.e_phentsize = *((Elf32_Half *)&str[42]);
       printf("program header table entry size:%d\n",elf_h.e_phentsize);
       elf_h.e_phnum = *((Elf32_Half *)&str[44]);
       printf("program header table entry count:%d\n",elf_h.e_phnum);
      
       /*
       *read program header table
       */
       int got_addr = 0;
       int p_strtab_addr = 0;
       int p_strtab_size = 0;
       int p_symbol_addr = 0;
       int p_symbol_size = 0;
       int lib_name = 0;

       int plt_size = 0;
       int plt_type = 0;
       int plt_rel_addr = 0;

       int rel_addr = 0;
       int rel_per_size = 0;
       int rel_total_size = 0;
       int rela_addr = 0;
       int rela_per_size = 0;
       int rela_total_size = 0;
       int init_function_addr = 0;
       int fini_function_addr = 0;
       int soname = 0;
       int lib_path = 0;

       int string_addr = 0;
       int base_addr = 0;

        int program_header = elf_h.e_phoff;
        printf("read program header information:\n");
	     for(int j = 1; j <= elf_h.e_phnum;j++)
	     {       
		printf("Segment %d\n",j);
                printf("Segment type:  ");
		elf_p.p_type = *((Elf32_Word *)&str[program_header]);
		switch(elf_p.p_type){
		   case 0:
		       printf("undefined\n");
		       break;
		   case 1:
		       printf("PT_LOAD\n");
		       break;
		   case 2:
		       printf("PT_DYNAMIC\n");
		       break;
		   case 3:
		       printf("PT_INTERP\n");
		       break;
		   case 4:
		       printf("PT_NOTE\n");
		       break;
		   case 5:
		       printf("PT_SHLIB\n");
		       break;
		   case 6:
		       printf("PT_PHDR\n");
		       break;
		   default:
		       printf("0x%x\n",elf_p.p_type);
		       break;
		}
		elf_p.p_offset = *((Elf32_Off *)&str[program_header+4]);
		printf("Segment offset: 0x%x\n",elf_p.p_offset);
		elf_p.p_vaddr = *((Elf32_Addr *)&str[program_header+8]);
		printf("Segment virtual address: 0x%x\n",elf_p.p_vaddr);
		elf_p.p_paddr = *((Elf32_Addr *)&str[program_header+12]);
		printf("Segment physical address: 0x%x\n",elf_p.p_paddr);
		elf_p.p_filesz = *((Elf32_Word *)&str[program_header+16]);
		printf("Segment size in file: 0x%x\n",elf_p.p_filesz);
		elf_p.p_memsz = *((Elf32_Word *)&str[program_header+20]);
		printf("Segment size in memory: 0x%x\n",elf_p.p_memsz);
		elf_p.p_flags = *((Elf32_Word *)&str[program_header+24]);
		printf("Segment flags: %d\n",elf_p.p_flags);
		elf_p.p_align = *((Elf32_Word *)&str[program_header+28]);
		printf("Segment alignment: %d\n",elf_p.p_align);
		printf("****************************************");
		program_header += elf_h.e_phentsize;  

                /*
                 *read the dynamic segment infomation
                 */
                
                if(elf_p.p_type == 2)
                {      
                    int dynamic_offset = elf_p.p_offset;
                    for(int i = 0; i < elf_p.p_memsz / sizeof(Elf32_Dyn); i++)
                    {
                        elf_dyn.d_tag = *((Elf32_Sword *)&str[dynamic_offset]);
                        switch(elf_dyn.d_tag){
                            case 0:
                                  break;
                            case 1:
                                 elf_dyn.d_un.d_val = *((Elf32_Word *)&str[dynamic_offset+4]);
                                 break;
                            case 2: 
                                 elf_dyn.d_un.d_val = *((Elf32_Word *)&str[dynamic_offset+4]);
				 plt_size = elf_dyn.d_un.d_val;
                 	      	 break;
                            case 3:
                                 elf_dyn.d_un.d_ptr = *((Elf32_Addr *)&str[dynamic_offset+4]);  
				 got_addr = elf_dyn.d_un.d_ptr;
				 break;      
                            case 4:
                                 elf_dyn.d_un.d_ptr = *((Elf32_Addr *)&str[dynamic_offset+4]);
				 break;
 		            case 5:
                                 elf_dyn.d_un.d_ptr = *((Elf32_Addr *)&str[dynamic_offset+4]);
                                 p_strtab_addr = elf_dyn.d_un.d_ptr;
				 break;
 			    case 6:
                                 elf_dyn.d_un.d_ptr = *((Elf32_Addr *)&str[dynamic_offset+4]);
                                 p_symbol_addr = elf_dyn.d_un.d_ptr;
 				 break;
			    case 7:
                                 elf_dyn.d_un.d_ptr = *((Elf32_Addr *)&str[dynamic_offset+4]);
			         rela_addr =  elf_dyn.d_un.d_ptr;
				 break;
                            case 8:
                                 elf_dyn.d_un.d_val = *((Elf32_Word *)&str[dynamic_offset+4]);
      			         rela_total_size =  elf_dyn.d_un.d_val;
 				 break;
			    case 9:
                                 elf_dyn.d_un.d_val = *((Elf32_Word *)&str[dynamic_offset+4]);
			         rela_per_size =  elf_dyn.d_un.d_val;
				 break;
	    	    	    case 10:
                                 elf_dyn.d_un.d_val = *((Elf32_Word *)&str[dynamic_offset+4]);
                                 p_strtab_size = elf_dyn.d_un.d_val;
				 break;
			    case 11:
                                 elf_dyn.d_un.d_val = *((Elf32_Word *)&str[dynamic_offset+4]);
 				 p_symbol_size = elf_dyn.d_un.d_val;
				 break;
                            case 12:
                                 elf_dyn.d_un.d_ptr = *((Elf32_Addr *)&str[dynamic_offset+4]);
				 init_function_addr = elf_dyn.d_un.d_ptr;
				 break;
 			    case 13:
                                 elf_dyn.d_un.d_ptr = *((Elf32_Addr *)&str[dynamic_offset+4]);
				 fini_function_addr = elf_dyn.d_un.d_ptr;
				 break;
                            case 14:
                                 elf_dyn.d_un.d_val = *((Elf32_Word *)&str[dynamic_offset+4]);
                                 soname = elf_dyn.d_un.d_val;
				 break;
			    case 15:
                                 elf_dyn.d_un.d_val = *((Elf32_Word *)&str[dynamic_offset+4]);
				 lib_path = elf_dyn.d_un.d_val;
                                 break;
                            case 16:
                                 break;
 			    case 17:
                                 elf_dyn.d_un.d_val = *((Elf32_Word *)&str[dynamic_offset+4]);
 				 break;
			    case 18:
                                 elf_dyn.d_un.d_val = *((Elf32_Word *)&str[dynamic_offset+4]);
				 rel_total_size =  elf_dyn.d_un.d_val;
				 break;
	    	    	    case 19:
                                 elf_dyn.d_un.d_val = *((Elf32_Word *)&str[dynamic_offset+4]);
			  	 rel_per_size = elf_dyn.d_un.d_val;
				 break;
			    case 20:
                                 elf_dyn.d_un.d_val = *((Elf32_Word *)&str[dynamic_offset+4]);
                                 plt_type = elf_dyn.d_un.d_ptr;
				 break;
                            case 21:
                                 elf_dyn.d_un.d_ptr = *((Elf32_Addr *)&str[dynamic_offset+4]);
				 break;
                            case 22:
                                 break;
                            case 23:
                                 elf_dyn.d_un.d_ptr = *((Elf32_Addr *)&str[dynamic_offset+4]);
                                 plt_rel_addr = elf_dyn.d_un.d_ptr;
				 break;
       		     	    case 0x70000000:
                                 break;
               	  	    case 0x7fffffff:
				 break;
                         default:
                                 break;          
                        }
                      
                        dynamic_offset += sizeof(Elf32_Dyn);
                        
                    }
                }
                   
              }  
              printf("\n");
                

             /*
              *read the dynamic symbol table 
             */
               int count_i = 0;
               int temp_symbol_addr = p_symbol_addr - 0x8048000;
               int temp_str_addr = p_strtab_addr - 0x8048000;
               while(1)
               {            
		       elf_dynsym.st_name = *((Elf32_Word *)&str[temp_symbol_addr]);   
		       elf_dynsym.st_value =  *((Elf32_Addr *)&str[temp_symbol_addr+4]);
		       elf_dynsym.st_size = *((Elf32_Word *)&str[temp_symbol_addr+8]);
		       elf_dynsym.st_info = str[temp_symbol_addr+12];
		       elf_dynsym.st_other =  str[temp_symbol_addr+13];
		       elf_dynsym.st_shndx = *((Elf32_Half *)&str[temp_symbol_addr+14]);
                     if((elf_dynsym.st_name != 0 || elf_dynsym.st_value != 0 ||  elf_dynsym.st_size != 0 || elf_dynsym.st_info !=  0 ||  elf_dynsym.st_other != 0 || elf_dynsym.st_shndx != 0) || count_i == 0 )
		       {
                               //printf("[%d]\n",count_i);
		               if( elf_dynsym.st_name <= p_strtab_size && elf_dynsym.st_name >= 0)
		               { 
				       if(str[temp_str_addr+elf_dynsym.st_name]!='\0'){
					  printf("symbol_name:%s\n",&str[temp_str_addr+elf_dynsym.st_name]);
                                          printf("symbol_value:0x%x\n",elf_dynsym.st_value);
				          printf("symbol_size:0x%x\n",elf_dynsym.st_size);
				          printf("symbol_info:0x%x\n",elf_dynsym.st_info);
			                  printf("symbol_other:0x%x\n",elf_dynsym.st_other);
				          printf("symbol_shndx:0x%x\n",elf_dynsym.st_shndx);
				          printf("************************\n");}
                                       //else
                                         // printf("symbol_name:0x%x\n",elf_dynsym.st_name);
                                         
                               }
                              /* else
                                       printf("symbol_name:0x%x\n",elf_dynsym.st_name);

                               printf("symbol_value:0x%x\n",elf_dynsym.st_value);
			       printf("symbol_size:0x%x\n",elf_dynsym.st_size);
			       printf("symbol_info:0x%x\n",elf_dynsym.st_info);
	                       printf("symbol_other:0x%x\n",elf_dynsym.st_other);
			       printf("symbol_shndx:0x%x\n",elf_dynsym.st_shndx);
			       printf("************************\n");	*/
			       temp_symbol_addr+=16;
		               count_i++;
                       }
                       else
                       {
 				break;
		       }
       		      
	       }
   
               printf("\n");
            
               /*
                *read the runtime plt relocation table
                */
               printf("read plt relocation table info:\n");
               int dlopen_addr;
               int puts_addr;
               int scanf_addr;
               int dlopen_got_addr;
               int puts_got_addr;
               int scanf_got_addr;
               
               int temp_plt_rel_addr = plt_rel_addr - 0x8048000;
/*
               printf("0x%x\n",temp_plt_rel_addr);
               printf("0x%x\n",plt_type);
               printf("0x%x\n",plt_size);

               printf("0x%x\n",rela_addr);
               printf("0x%x\n",rela_total_size);
               printf("0x%x\n",rela_per_size);

               printf("0x%x\n",rel_addr);
               printf("0x%x\n",rel_total_size);
               printf("0x%x\n",rel_per_size);
*/

               for(int i = 0; i < plt_size / sizeof(Elf32_Rel); i++)
               {
		    if(plt_type == 7)
                     {  
                        //Rela
                        elf_rela.r_offset = *((Elf32_Addr *)&str[temp_plt_rel_addr]);
			elf_rela.r_info = *((Elf32_Word *)&str[temp_plt_rel_addr+4]);
                        printf("relocation_offset:  \n",elf_rela.r_offset);
                        printf("relocation_info:   \n",elf_rela.r_info);
                     }
                     else if(plt_type== 17)
                     { 
                        //Rel
                        elf_rel.r_offset = *((Elf32_Addr *)&str[temp_plt_rel_addr]);
			elf_rel.r_info = *((Elf32_Word *)&str[temp_plt_rel_addr+4]);
                        printf("relocation_offset:    0x%x\n",elf_rel.r_offset);
                        printf("relocation_info->");
                        int and_value = elf_rel.r_info & 0xff;
                        int shr_value = elf_rel.r_info >> 8;
                        int temp_symbol_name = *( (Elf32_Word *)&str[p_symbol_addr - 0x8048000+ shr_value * 16] );
                        if(str[p_strtab_addr - 0x8048000 + temp_symbol_name] != 0)
                        {
                             printf("      relocation_symbol_name:%s\n",&str[p_strtab_addr - 0x8048000 + temp_symbol_name]);
                        }
                        printf("                       relocation_type:0x%x\n\n",and_value);

                     }
   
                     temp_plt_rel_addr += sizeof(Elf32_Rel);
                  }

                 printf("\n"); 
     
     }
  
     return 0;
}
