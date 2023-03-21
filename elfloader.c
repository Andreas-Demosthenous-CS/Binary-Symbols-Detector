//Andreas Demosthenous - 1022308 - Symbol inspector homework
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <libelf.h>
#include <gelf.h>


#define DIE(...) \
    do { \
        fprintf(stderr, __VA_ARGS__); \
        fputc('\n', stderr); \
        exit(EXIT_FAILURE); \
    } while (0)


//Function to convert symbol to bsd format given the symbol and the section the symbol belongs to 
char getSymbolType(GElf_Shdr section_header, GElf_Sym symbol)
{
    char type;

    if (ELF64_ST_BIND(symbol.st_info) == STB_GNU_UNIQUE)
    {
        type = 'u';
    }
    else if (ELF64_ST_BIND(symbol.st_info) == STB_WEAK)
    {
        type = 'W';
        if (symbol.st_shndx == SHN_UNDEF)
        {
            type = 'w';
        }
    }
    else if (ELF64_ST_BIND(symbol.st_info) == STB_WEAK && ELF64_ST_TYPE(symbol.st_info) == STT_OBJECT)
    {
        type = 'V';
        if (symbol.st_shndx == SHN_UNDEF)
        {
            type = 'v';
        }
    }
    else if (symbol.st_shndx == SHN_UNDEF)
    {
        type = 'U';
    }
    else if (symbol.st_shndx == SHN_ABS)
    {
        type = 'A';
    }
    else if (symbol.st_shndx == SHN_COMMON)
    {
        type = 'C';
    }
    else if (section_header.sh_type == SHT_NOBITS && section_header.sh_flags == (SHF_ALLOC | SHF_WRITE))
    {
        type = 'B';
    }
    else if (section_header.sh_type == SHT_PROGBITS && section_header.sh_flags == SHF_ALLOC)
    {
        type = 'R';
    }
    else if (section_header.sh_type == SHT_PROGBITS && section_header.sh_flags == (SHF_ALLOC | SHF_WRITE))
    {
        type = 'D';
    }

    else if (section_header.sh_type == SHT_PROGBITS && section_header.sh_flags == (SHF_ALLOC | SHF_EXECINSTR))
    {

        type = 'T';
    }
    else if (section_header.sh_type == SHT_DYNAMIC)
    {
        type = 'D';
    }
    else
    {
        type = ('t' - 32);
    }

    if (ELF64_ST_BIND(symbol.st_info) == STB_LOCAL && type != '?')
    {
        type += 32;
    }

    return type;

}

//Function to print the symbol table 
void print_symbol_table(Elf *elf, Elf_Scn *scn, size_t shstrndx) {

    Elf_Data *data;
    GElf_Shdr shdr;
    int count = 0;

    /* Get the descriptor.  */
    if (gelf_getshdr(scn, &shdr) != &shdr)
        DIE("(getshdr) %s", elf_errmsg(-1));

   //gets the contents of the section
    data = elf_getdata(scn, NULL);

   //gets the amount of entries(symbols)
    count = shdr.sh_size / shdr.sh_entsize;

   
    //iterating the symbol table 	
    for (int i = 0; i < count; ++i) {
        GElf_Sym sym;
	//Retrieves the symbol with i index
        gelf_getsym(data, i, &sym);
	
	//when the value is not empty => find and print its relevant section
	if(sym.st_value){
		/* Get the relevant section index for the symbol */
                Elf_Scn *symbol_section = elf_getscn(elf, sym.st_shndx);
                
		if (symbol_section) {
                    GElf_Shdr symbol_section_header;
		    //get relevant section header of the relevant section index
                    gelf_getshdr(symbol_section, &symbol_section_header);
                    
		    //printing the symbol with the relevant section 
		    fprintf(stderr, "%40s %c  %016lx  %10s\n", elf_strptr(elf, shdr.sh_link, sym.st_name),
 			getSymbolType(symbol_section_header, sym), sym.st_value, 
			elf_strptr(elf, shstrndx, symbol_section_header.sh_name));
                }
	}
	//Printing the symbol without the relevant section as the value is empty
	else
        	fprintf(stderr, "%40s %c  %016lx \n",elf_strptr(elf, shdr.sh_link, sym.st_name),
		getSymbolType(shdr, sym), sym.st_value);
    }
}

void load_file(char *filename) {

    Elf *elf;
    Elf_Scn *symtab, *dynsym;   
    bool symtab_found = 0;
    /* Initilization.  */
    if (elf_version(EV_CURRENT) == EV_NONE) 
        DIE("(version) %s", elf_errmsg(-1));

    int fd = open(filename, O_RDONLY);

    elf = elf_begin(fd, ELF_C_READ, NULL); 
    if (!elf) 
        DIE("(begin) %s", elf_errmsg(-1));

    /* Loop over sections.  */
    Elf_Scn *scn = NULL;
    GElf_Shdr shdr;
    size_t shstrndx;
    if (elf_getshdrstrndx(elf, &shstrndx) != 0)  
        DIE("(getshdrstrndx) %s", elf_errmsg(-1));

    //iterating sections to find .symtab and .dynsym
    int s_index = 0;
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        if (gelf_getshdr(scn, &shdr) != &shdr)
            DIE("(getshdr) %s", elf_errmsg(-1));
        
	s_index++;

        /* Locate symbol table.  */
        if (!strcmp(elf_strptr(elf, shstrndx, shdr.sh_name), ".symtab")){ 
            symtab = scn;
	    symtab_found = 1;
	}
        /* Locate dynamic symbol table.  */
        if (!strcmp(elf_strptr(elf, shstrndx, shdr.sh_name), ".dynsym")){
            dynsym = scn;
        }

    }
    //If .symtab section is found => Binary is not stripped => 
    //print the symbol table. If not => print the corresponding message
    if(symtab_found){
	fprintf(stderr, "Printing symbol table\n");
	print_symbol_table(elf, symtab, shstrndx);
    }
    else
	fprintf(stderr, "Binary is stripped. Symbol table is missing.\n");
	
    fprintf(stderr, "Printing dynamic symbol table\n");
    print_symbol_table(elf, dynsym, shstrndx);

}

int main(int argc, char *argv[]) {

    if (argc < 2) 
        DIE("usage: elfloader <filename>");
    
    load_file(argv[1]);

    return 1;
}
