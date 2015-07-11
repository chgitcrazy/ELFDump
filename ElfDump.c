#include <stdio.h>
#include <stdlib.h>
//#include <types.h>
//#include </usr/include/sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include </usr/include/elf.h>
#include <memory.h>
#include <math.h>

#define FALSE 0
#define TURE 1
#define MAX_SIZE 20000

//elf header 
static Elf32_Ehdr elf_h;
//elf section header table
static Elf32_Shdr elf_s;
//elf symbol table
static Elf32_Sym  elf_sym;
//elf dynamic section
static Elf32_Sym elf_dynsym;
//elf .rel.dyn section
static Elf32_Rel elf_rel_dyn;
//elf .rel.plt section
static Elf32_Rel elf_rel_plt;

//save section name
char** sectionName;
//save symbol name
char **symbolName;

  int sysbol_addr = 0;
       int sysbol_size = 0;
       int sysbol_entsize = 0;
       int addr_addr = 0;
       int interp_addr = 0;
       int interp_size = 0;
       int dynsym_addr = 0;
       int dynsym_size = 0;
       int dynsym_entsize = 0;
       int dynstr_addr = 0;
       int dynstr_size = 0;
       int rel_dyn_addr = 0;
       int rel_dyn_size = 0;
       int rel_dyn_entsize = 0;
       int rel_plt_addr = 0;
       int rel_plt_size = 0;
       int rel_plt_entsize = 0;
       int plt_addr = 0;
       int plt_size = 0;
       int plt_entsize = 0;

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
 

int ReadHeader(int fd)
{
     //save the bytes from the elf file
     char str[MAX_SIZE]; 
     //save the setion_name
     //char **section_str;

     //save the number of byte reading from the elf file
     int num = 0;
     
     /*
     *because the section header is like an array , 
     *so there are a lot of section headers,
     *every section header has the attribute `section_name` , `section_type` , `section_flags` ....etc.
     */
     int *section_name;
     int *section_type;
     int *section_flags;
     int *section_addr;
     int *section_offset;
     int *section_size;
     int *section_link;
     int *section_info;
     int *section_addralign;
     int *section_entsize;

     //init the str array
     memset(str,0,MAX_SIZE);

     //read contents from the specific elf file
     num = read(fd,str,MAX_SIZE);
      
     /*
      *if the file format is `ELF` , then parse it ,otherwise exit
      */
     if((str[0] == 0x7f) && (str[1] == 'E') && (str[2] == 'L') && (str[3] == 'F'))
     {
        /*
         *read the elf header information
        */
        printf("1.elf header information.........\n\n");
        printf("class is : ");
        switch(str[4]){
              case 0:
                    printf("invalid file\n"); 
                    break;
              case 1:
                    printf("32-bit file\n");
                    break;
              case 2:
                    printf("64-bit file\n");
                    break;
              default:
                   break;
        }

        printf("code format is : ");
        switch(str[5]){
              case 0:
                    printf("invalid code format\n"); 
                    break;
              case 1:
                    printf("little-bidian code format\n");
                    break;
              case 2:
                    printf("big-bidian code format\n");
                    break;
              default:
                   break;
        }

        printf("elf version is : ");
        if(str[6] == 1){
              printf("current version\n");
        }else{
              printf("NULL\n");
        }
         
        printf("type is : ");
        elf_h.e_type = *((Elf32_Half *)&str[16]);
        switch(elf_h.e_type){
            case 0:  
                  printf("unknown file type\n");
                  break;
            case 1:
                  printf("relocateble file type\n");
                  break;
            case 2:
                  printf("executable file type\n");
                  break;
            case 3:
                  printf("shared objective file type\n");
                  break;
            case 4:
                  printf("core file type\n");
                  break;
            default:
                  break;

        }
       printf("cpu machine is : ");
       elf_h.e_machine = *((Elf32_Half *)&str[18]);
       switch(elf_h.e_machine){
           case 0:
                printf("unknown architecture\n");
                break;
           case 1:
                printf("AT&T WE 32100\n");
                break;
           case 2:
                printf("SPARC\n");
                break;
           case 3:
                printf("Intel 80386\n");
                break;
           case 4:
                printf("Motorola 68000\n");
                break;
           case 5:
                printf("Motorola 88000\n");
                break;
           case 7:
                printf("Intel 80860\n");
                break;
           case 8:
                printf("MIPS RS3000\n");
                break;
           default:
                printf("%d\n",elf_h.e_machine);
                break;
       }
        
       printf("version is : ");
       elf_h.e_version = *((Elf32_Word *)&str[20]);
       switch(elf_h.e_version){
           case 0:
                printf("Invalid Elf version\n");
                break;
           case 1:
                printf("current version\n");
                break;
           default:
                break;
       }

       elf_h.e_entry = *((Elf32_Addr *)&str[24]);
       printf("entry point virtual address:0x%x\n",elf_h.e_entry);
       
       elf_h.e_phoff = *((Elf32_Off *)&str[28]);
       printf("program header table file offset:0x%x\n",elf_h.e_phoff);

       elf_h.e_shoff = *((Elf32_Off *)&str[32]);
       printf("section header table file offset:0x%x\n",elf_h.e_shoff);
      
       elf_h.e_flags = *((Elf32_Word *)&str[36]);
       printf("Processor-specific flags:0x%x\n",elf_h.e_flags);

       elf_h.e_ehsize = *((Elf32_Word *)&str[40]);
       printf("ELF header size in bytes:0x%x\n",elf_h.e_ehsize);

       elf_h.e_phentsize = *((Elf32_Half *)&str[42]);
       printf("program header table item size:0x%x\n",elf_h.e_phentsize);

       elf_h.e_phnum = *((Elf32_Half *)&str[44]);
       printf("program header table item count:0x%x\n",elf_h.e_phnum);

       elf_h.e_shentsize = *((Elf32_Half *)&str[46]);
       printf("section header table item size:0x%x\n",elf_h.e_shentsize);

       elf_h.e_shnum = *((Elf32_Half *)&str[48]);
       printf("section header table item count:0x%x\n",elf_h.e_shnum);
       
       elf_h.e_shstrndx = *((Elf32_Half *)&str[50]);
       printf("section header string table index:0x%x\n",elf_h.e_shstrndx);

       printf("\n2. section header information......\n");

       /*
       *read the elf section header information 
       */       
        section_name = malloc(sizeof(int) * elf_h.e_shnum);
        section_type = malloc(sizeof(int) * elf_h.e_shnum);
        section_flags= malloc(sizeof(int) * elf_h.e_shnum);
        section_addr = malloc(sizeof(int) * elf_h.e_shnum);
        section_offset = malloc(sizeof(int) * elf_h.e_shnum);
        section_size = malloc(sizeof(int) * elf_h.e_shnum);
        section_link = malloc(sizeof(int) * elf_h.e_shnum);
        section_info = malloc(sizeof(int) * elf_h.e_shnum);
        section_addralign = malloc(sizeof(int) * elf_h.e_shnum);
        section_entsize = malloc(sizeof(int) * elf_h.e_shnum);

     
       int sectionOffset = elf_h.e_shoff;

       for(int i = 0; i < elf_h.e_shnum; i++)
       {
           
           section_name[i] = *((Elf32_Word *)&str[sectionOffset]);
           
           section_type[i] = *((Elf32_Word *)&str[sectionOffset+4]);
          
           section_flags[i] = *((Elf32_Word *)&str[sectionOffset+8]);
          
           section_addr[i] = *((Elf32_Addr *)&str[sectionOffset+12]);
          
           section_offset[i] = *((Elf32_Off *)&str[sectionOffset+16]);
         
           section_size[i] = *((Elf32_Word *)&str[sectionOffset+20]);
           
           section_link[i] = *((Elf32_Word *)&str[sectionOffset+24]);
          
           section_info[i] = *((Elf32_Word *)&str[sectionOffset+28]);
         
           section_addralign[i] = *((Elf32_Word *)&str[sectionOffset+32]);
      
           section_entsize[i] = *((Elf32_Word *)&str[sectionOffset+36]);

           sectionOffset += elf_h.e_shentsize;

       }

       int string_table_offset = section_offset[elf_h.e_shstrndx];
     
       
       //output the first section header table information
       printf("%s\n","section information...........");
       printf("      0th section(UNDEF):\n");
       printf("          section_name:%d\n",section_name[0]);
       printf("          section_type:%d\n",section_type[0]);
       printf("          section_flags:%d\n",section_flags[0]);
       printf("          section_addr:0x%x\n",section_addr[0]);
       printf("          section_offset:0x%x\n",section_offset[0]);
       printf("          section_size:0x%x\n",section_size[0]);
       printf("          section_link:%d\n",section_link[0]);
       printf("          section_info:%d\n",section_info[0]);
       printf("          section_addralign:%d\n",section_addralign[0]);
       printf("          section_entsize:%d\n",section_entsize[0]);
      

       sectionName = (char**)malloc(elf_h.e_shnum);
       sectionName[0] = NULL;
       //output the remain section header table information
       for(int i = 1; i < elf_h.e_shnum; i++)
       {
          printf("      %dth section:\n",i);
          if(str[string_table_offset+section_name[i]] != 0)
          {
            sectionName[i] = &str[string_table_offset+section_name[i]];
            printf("          section_name:%s\n",sectionName[i]);
          }else{
            sectionName[i] = NULL;
          }
          
          if(strcmp(sectionName[i],".symtab") == 0)
          {
              sysbol_addr = section_offset[i];
              sysbol_size = section_size[i];
              sysbol_entsize = section_entsize[i];
          }
          if(strcmp(sectionName[i],".strtab") == 0)
          {
              addr_addr = section_offset[i];
          }
          if(strcmp(sectionName[i],".interp") == 0)
          {
              interp_addr = section_offset[i];
              interp_size = section_size[i];
          }
          if(strcmp(sectionName[i],".dynsym") == 0)
          {
              dynsym_addr = section_offset[i];
              dynsym_size = section_size[i];
              dynsym_entsize = section_entsize[i];
          }
          if(strcmp(sectionName[i],".dynstr") == 0)
          {
              dynstr_addr = section_offset[i];
              dynstr_size = section_size[i];
          }  
          if(strcmp(sectionName[i],".rel.dyn") == 0)
          {
              rel_dyn_addr = section_offset[i];
              rel_dyn_size = section_size[i];
              rel_dyn_entsize = section_entsize[i];
          }
          if(strcmp(sectionName[i],".rel.plt") == 0)
          {
              rel_plt_addr = section_offset[i];
              rel_plt_size = section_size[i];
              rel_plt_entsize = section_entsize[i];
          }
          if(strcmp(sectionName[i],".plt") == 0)
          {
              plt_addr = section_offset[i];
              plt_size = section_size[i];
              plt_entsize = section_entsize[i];
          }
          printf("          section_type:");
          switch(section_type[i]){
             case 0:
                   printf("this section header is inactivity,no correstponding section\n");
                   break;
             case 1:
                   printf("progbits:program definition\n");
                   break;
             case 2:
                   printf("symtab\n");
                   break;
             case 3:
                   printf("strtab\n");
                   break;
             case 4:
                   printf("relatab\n");
                   break;
             case 5:
                   printf("hashtab\n");
                   break;
             case 6:
                   printf("dynamic\n");
                   break;
             case 7:
                   printf("note\n");
                   break;
             case 8:
                   printf("nobits\n");
                   break;
             case 9:
                   printf("reltab\n");
                   break;
             case 10:
                   printf("shlib\n"); 
                   break;
             case 11:
                   printf("dynsym\n");
                   break;
             default:
                   printf("0x%x\n",section_type[i]);
                   break;
       }
       
	  printf("          section_flags:%d\n",section_flags[i]);
	  printf("          section virtual addr:0x%x\n",section_addr[i]);
	  printf("          section file offset:0x%x\n",section_offset[i]);
	  printf("          section_size:0x%x\n",section_size[i]);
	  printf("          section_link:%d\n",section_link[i]);
	  printf("          section_info:%d\n",section_info[i]);
	  printf("          section_addralign:%d\n",section_addralign[i]);
	  printf("          section in item size:%d\n",section_entsize[i]);
   
       }
      

  
       /*
        *read the section .interp information
        */
     /*  printf("\n");
       printf(".interp:\n");
       for(int i = 0; i < interp_size; i++)
            printf("%c",str[interp_addr+i]);
       printf("\n");*/

       /*
        *read the section .dynsym information
        */
      /* printf("\n");
       printf(".dynsym  information:\n");
       int dynsym_offset = dynsym_addr;
       for(int i = 0; i < dynsym_size / dynsym_entsize; i++)
       {
           elf_dynsym.st_name = *((Elf32_Word *)&str[dynsym_offset]);
           int k = 0;
           while(str[dynstr_addr + elf_dynsym.st_name + k] != 0)
           {
               if(k == 0)
               {
                  printf("dynsym_name:");
               }
               printf("%c",str[dynstr_addr + elf_dynsym.st_name + k]);
               k++;
           }
           printf("   ");
           elf_dynsym.st_value = *((Elf32_Addr *)&str[dynsym_offset+4]);
           printf("st_value:0x%x    ",elf_dynsym.st_value);

           elf_dynsym.st_size = *((Elf32_Word *)&str[dynsym_offset+8]);
           printf("st_size:0x%x    ",elf_dynsym.st_size);

           elf_dynsym.st_info = str[dynsym_offset+12];
           printf("st_info:0x%x    ",elf_dynsym.st_info);

           elf_dynsym.st_other = str[dynsym_offset+13];
           printf("st_other:0x%x    ",elf_dynsym.st_other);

           elf_dynsym.st_shndx = *((Elf32_Half *)&str[dynsym_offset+14]);
           printf("st_shndx:0x%x\n",elf_dynsym.st_shndx);

           dynsym_offset += 16;  
       }

       printf("\n");*/
       /*
        *read the section .symbol information
        */  
      

      /* printf(".symbol  information:\n");
 
       int sysbol_offset = sysbol_addr;
 
       for(int i = 0; i < sysbol_size / sysbol_entsize; i++)
       {
           printf("[%d]\n",i);
           elf_sym.st_name = *((Elf32_Word *)&str[sysbol_offset]);
           if(str[addr_addr + elf_sym.st_name] != 0)
           {
               printf("symbol name:%s\n",&str[addr_addr + elf_sym.st_name]);
           }     
           elf_sym.st_value = *((Elf32_Addr *)&str[sysbol_offset+4]);
           printf("symbol value(address or else):0x%x\n", elf_sym.st_value);

           elf_sym.st_size = *((Elf32_Word *)&str[sysbol_offset+8]);
           printf("st_size:0x%x\n", elf_sym.st_size);

           elf_sym.st_info = str[sysbol_offset+12];
           printf("   st_bind:");
           switch(elf_sym.st_info >> 4){
              case 0:
              printf("STB_LOCAL\n");break;
              case 1:
              printf("STB_GLOBAL\n");break;
              case 2:
              printf("STB_WEAK\n");break;
              case 13:
              printf("STB_LOPROC\n");break;
              case 15:
              printf("STB_HIPROC\n");break;
              default:
              printf("%d\n",elf_sym.st_info >> 4);
           }
           printf("   st_type:");
           switch(elf_sym.st_info & 0xf){
              case 0:
              printf("STT_NOTYPE\n");break;
              case 1:
              printf("STT_OBJECT\n");break;
              case 2:
              printf("STT_FUNC\n");break;
              case 3:
              printf("STT_SECTION\n");break;
              case 4:
              printf("STT_FILE\n");break;
              case 13:
              printf("STT_LOPROC\n");break;
              case 15:
              printf("STT_HIPROC\n");break;
              default:
              printf("%d\n",elf_sym.st_info & 0xf);
           }
           
           elf_sym.st_other = str[sysbol_offset+13];
           printf("st_other:0x%x\n", elf_sym.st_other);

           elf_sym.st_shndx = *((Elf32_Half *)&str[sysbol_offset+14]);
           printf("st_shndx:0x%x->", elf_sym.st_shndx);
           if(elf_sym.st_shndx < elf_h.e_shnum && elf_sym.st_shndx > 0)
           {
               if(sectionName[elf_sym.st_shndx] != NULL)
               {
               printf("  section:%s\n\n",sectionName[elf_sym.st_shndx]);
               }
           }else{
               printf("\n\n");
           }

           sysbol_offset += sysbol_entsize;  
       }


      printf("\n");*/

     
      /*
       *read the relocation dyn section 
       */  
      printf(".rel.dyn information:\n");
      int rel_dyn_offset = rel_dyn_addr;
      for(int i = 0;  i < rel_dyn_size / rel_dyn_entsize; i++)
      {
          elf_rel_dyn.r_offset = *((Elf32_Addr *)&str[rel_dyn_offset]);

          printf("r_offset:0x%x      ",elf_rel_dyn.r_offset);
          elf_rel_dyn.r_info = *((Elf32_Addr *)&str[rel_dyn_offset + 4]);

          int elf_rel_dyn_symbol = elf_rel_dyn.r_info >> 8;
          int elf_rel_dyn_symbol_name = *((int *)&str[dynsym_addr + elf_rel_dyn_symbol * 16]);
          int elf_rel_dyn_type =  (unsigned char)elf_rel_dyn.r_info;
         
          if(str[dynstr_addr + elf_rel_dyn_symbol_name] != 0)          
          {   
              printf("sym_name:");
              printf("%s",&str[dynstr_addr + elf_rel_dyn_symbol_name]);
          }
          printf("    ");
          printf("sym_type:0x%x\n",elf_rel_dyn_type);
 
          rel_dyn_offset += 8;
      }

      printf("\n");

      /*
       *read the relocation plt section 
       */
      printf(".rel.plt information:\n");
      int rel_plt_offset = rel_plt_addr;
      for(int i = 0;  i < rel_plt_size / rel_plt_entsize; i++)
      {
          elf_rel_plt.r_offset = *((Elf32_Addr *)&str[rel_plt_offset]);
          printf("r_offset:0x%x      ",elf_rel_plt.r_offset);
          elf_rel_plt.r_info = *((Elf32_Addr *)&str[rel_plt_offset + 4]);

          int elf_rel_plt_symbol = elf_rel_plt.r_info >> 8;
          int elf_rel_plt_symbol_name = *((int *)&str[dynsym_addr + elf_rel_plt_symbol * 16]);
          int elf_rel_plt_type =  (unsigned char)elf_rel_plt.r_info;
          if(str[dynstr_addr + elf_rel_plt_symbol_name] != 0)          
          {
              printf("sym_name:");
              printf("%s",&str[dynstr_addr + elf_rel_plt_symbol_name]);
          }
          printf("    ");
          printf("sym_type:0x%x\n",elf_rel_plt_type);
                
           
          rel_plt_offset += 8;
      }

      printf("\n");
      
             
   }

}

   
int main(int argc , char **argv)
{
    int boolean;
    
    if(argc == 2)
    {
       boolean = OpenElf(argv[1]);
       if(boolean  == FALSE){
          return -1;
       }
       ReadHeader(boolean);
    }
    return 0;
}
