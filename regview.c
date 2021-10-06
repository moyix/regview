#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

typedef struct _FILETIME {
    uint32_t dwLowDateTime;
    uint32_t dwHighDateTime;
} FILETIME;

#define NK_ROOT 0x2c
#define NK_NODE 0x20
#define NK_LINK 0x10

// Offsets in registry hives are relative to the first hbin block,
// and point to the cell size (which we usually don't want).
// Convert them to the true file offset of the structure.
uint32_t convOff(unsigned int off) {
    return off + 0x1000 + 4;
}

typedef struct hiveVersion {
    uint32_t major;
    uint32_t minor;
    uint32_t release;
    uint32_t build;
} HiveVersion;

// Represents a node/key. Links to other node/keys (ie subkeys), and
// also to values and security descriptors.
typedef struct nk_cell {
    char signature[2];  // 'nk'
    short type;         // 0x2c for root, 0x20 for non-root, 0x10 for symlinks
    FILETIME modified;
    uint32_t u1;
    uint32_t parent;
    int32_t num_subkeys;
    uint32_t u2;
    uint32_t subkeys;
    uint32_t u3;
    int32_t num_values;
    uint32_t values;
    uint32_t security;
    uint32_t classname;
    uint32_t u4[5];
    unsigned short name_len;
    unsigned short classname_len;
    char name[1];
} NK;

// Note: lh and lf records only differ in the type of hash used,
// which we are ignoring.
typedef struct lh_cell {
    char signature[2];
    short num_entries;
} LH;

typedef struct ri_cell {
    char signature[2];
    short num_entries;
    uint32_t entries[1];
} RI;

typedef struct hashrec {
    uint32_t offset;
    char hash[4];       // First 4 chars of keyname for lf, base37 
} HashRec;

typedef struct hiveHeader {
    char signature[4];              // 'regf'
    uint32_t update_count1;
    uint32_t update_count2;
    FILETIME modified;
    HiveVersion version;
    uint32_t data_offset;
    uint32_t last_block;
    uint32_t unknown;           // Always 1
    unsigned char padding[0x1cc];
    uint32_t checksum;          // XOR of 0x00 through 0x1FC
} HiveHeader;

typedef struct blockHeader {
    char signature[4];          // 'hbin'
    uint32_t off;           // offset from the first hbin block
    uint32_t next;          // offset to the next hbin block
    uint32_t padding[2];    // unknown
    FILETIME modified;          // last modified time
    uint32_t block_size;
} BlockHeader;

#define WINDOWS_TICK 10000000
#define SEC_TO_UNIX_EPOCH 11644473600LL

unsigned WindowsTickToUnixSeconds(uint64_t windowsTicks)
{
     return (unsigned)(windowsTicks / WINDOWS_TICK - SEC_TO_UNIX_EPOCH);
}

// Print an NT time in human-readable format
void printNTTime(FILETIME *ft) {
    uint64_t ticks = ((uint64_t)ft->dwHighDateTime << 32) | ft->dwLowDateTime;
    time_t unix_time = WindowsTickToUnixSeconds(ticks);

    //printf("Last modification time: %02d/%02d/%04d %02d:%02d:%02d +%d ms UTC\n",
    //  s.wMonth, s.wDay, s.wYear, s.wHour, s.wMinute, s.wSecond, s.wMilliseconds);
    printf("Last modification time: %s", ctime(&unix_time));
     
    return;
}

// Print information about an nk record
void printNK(NK *nodeKey) {
    char *nkName = (char *) malloc(nodeKey->name_len + 1);
    if (!nkName) exit(1);
    strncpy(nkName, nodeKey->name, nodeKey->name_len);
    nkName[nodeKey->name_len] = '\0';
    printf("%.2s: type 0x%x parent 0x%x, %d subkeys at 0x%x, %d values at 0x%x, "
        "security descriptor at 0x%0x, name %s\n", nodeKey->signature,
        nodeKey->type, nodeKey->parent, nodeKey->num_subkeys, nodeKey->subkeys,
        nodeKey->num_values, nodeKey->values, nodeKey->security,
        nkName);
    free(nkName);
    return;
}

// Print only the name for a node/key
void printNKName(NK *nodeKey, int tabs) {
    for(int i = 0; i < tabs; i++) {
        printf(" ");
    }
    char *nkName = (char *) malloc(nodeKey->name_len + 1);
    if (!nkName) exit(1);
    strncpy(nkName, nodeKey->name, nodeKey->name_len);
    nkName[nodeKey->name_len] = '\0';
    printf("%s\n", nkName);
    free(nkName);

    return;
}

// Print a node and its subtree
void printSubTree(NK *root, FILE *regf, int level) {
    printNKName(root, level);
    if(root->num_subkeys == 0 || root->subkeys == 0 ||
        root->subkeys == 0xFFFFFFFF) {
        //printf("End of subtree, returning\n");
        return;
    }
    //printf("%d %x\n", root->num_subkeys, root->subkeys);

    LH lh;
    fseek(regf,convOff(root->subkeys),SEEK_SET);
    //printf("Reading entry at %x\n", convOff(root->subkeys));
    fread(&lh, sizeof(LH), 1, regf);

    if(!strncmp(lh.signature, "lh", 2) || !strncmp(lh.signature, "lf", 2)) {
        //printf("%d entries in this hashlist\n", lh.num_entries);
        if(lh.num_entries < 0) exit(1);
        if(root->num_subkeys != lh.num_entries) {
            printf("WARN: number of subkeys does not match, %d != %d\n",
                root->num_subkeys, lh.num_entries);
        }

        HashRec *hashes;
        hashes = (HashRec *) malloc(lh.num_entries * sizeof(HashRec));
        if (!hashes) exit(1);

        int nread = fread(hashes, sizeof(HashRec), lh.num_entries, regf);
        if (nread < lh.num_entries) {
            if(feof(regf))
                printf("Unexpected EOF while reading file.\n");
            if(ferror(regf)) {
                printf("fread failed, file error.\n");
                perror( "Read error (line 156)" );
            }
            exit(1);
        }

        //for(int i = 0; i < lh.num_entries; i++) {
        //  printf("%x\n", hashes[i].offset);
        //}

        // Read the nk entry that each lh hash entry points to
        // Note that since the length of the nk name is not known
        // ahead of time we have to read the structure twice
        for(int i = 0; i < lh.num_entries; i++) {
            NK *next;
            next = (NK *)malloc(sizeof(NK));
            if (!next) exit(0);

            //printf("Next nk entry at offset 0x%x\n", convOff(hashes[i].offset));
            fseek(regf, convOff(hashes[i].offset), SEEK_SET);
            fread(next, sizeof(NK), 1, regf);
            
            // re-read it
            int full_nk_size = sizeof(NK) + next->name_len - 1;
            next = (NK *)realloc(next, full_nk_size);
            fseek(regf, convOff(hashes[i].offset), SEEK_SET);
            fread(next, full_nk_size, 1, regf);
            
            printSubTree(next, regf, level+1);

            free(next);
        }
    }
    else if (!strncmp(lh.signature, "ri", 2)) {
        // Actually an ri record. These are lists of offsets
        // to li/lh records
        uint32_t *li_offsets = (uint32_t *)malloc(lh.num_entries * sizeof(uint32_t));
        if (!li_offsets) exit(1);
        int nread = fread(li_offsets, sizeof(uint32_t), lh.num_entries, regf);
        if (nread < lh.num_entries) {
            if(feof(regf))
                printf("Unexpected EOF while reading file.\n");
            if(ferror(regf)) {
                printf("fread failed, file error.\n");
                perror( "Read error (line 197)" );
            }
            exit(1);
        }
        for(int i = 0; i < lh.num_entries; i++) {
            LH lh2;
            fseek(regf,convOff(li_offsets[i]),SEEK_SET);
            //printf("Reading entry at %x\n", convOff(li_offsets[i]));
            fread(&lh2, sizeof(LH), 1, regf);

            if(!strncmp(lh2.signature, "lh", 2) || !strncmp(lh2.signature, "lf", 2)) {
                //printf("%d entries in this lh/lf list\n", lh2.num_entries);

                HashRec *hashes;
                hashes = (HashRec *) malloc(lh2.num_entries * sizeof(HashRec));
                if (!hashes) exit(1);

                int nread = fread(hashes, sizeof(HashRec), lh2.num_entries, regf);
                if (nread < lh2.num_entries) {
                    if(feof(regf))
                        printf("Unexpected EOF while reading file.\n");
                    if(ferror(regf)) {
                        perror( "Read error (line 223)" );
                    }
                    exit(1);
                }

                // Read the nk entry that each lh hash entry points to
                // Note that since the length of the nk name is not known
                // ahead of time we have to read the structure twice
                for(int i = 0; i < lh2.num_entries; i++) {
                    NK *next;
                    next = (NK *)malloc(sizeof(NK));
                    if (!next) exit(1);

                    //printf("Next nk entry at offset 0x%x\n", convOff(hashes[i].offset));
                    fseek(regf, convOff(hashes[i].offset), SEEK_SET);
                    fread(next, sizeof(NK), 1, regf);
                    
                    // re-read it
                    int full_nk_size = sizeof(NK) + next->name_len - 1;
                    next = (NK *)realloc(next, full_nk_size);
                    fseek(regf, convOff(hashes[i].offset), SEEK_SET);
                    fread(next, full_nk_size, 1, regf);
                    
                    printSubTree(next, regf, level+1);

                    free(next);
                }
            }
            else if (!strncmp(lh2.signature, "li", 2)) {
                //printf("%d entries in this li list\n", lh2.num_entries);
                uint32_t *nk_offsets = (uint32_t *)malloc(lh2.num_entries * sizeof(uint32_t));
                if (!nk_offsets) exit(1);
                int nread = fread(nk_offsets, sizeof(uint32_t), lh2.num_entries, regf);
                if (nread < lh2.num_entries) {
                    if(feof(regf))
                        printf("Unexpected EOF while reading file.\n");
                    if(ferror(regf)) {
                        perror("Read error (line 264)");
                    }
                    exit(1);
                }
                
                for(int i = 0; i < lh2.num_entries; i++) {
                    NK *next;
                    next = (NK *)malloc(sizeof(NK));
                    if (!next) exit(1);

                    //printf("Next nk entry at offset 0x%x\n", convOff(hashes[i].offset));
                    fseek(regf, convOff(nk_offsets[i]), SEEK_SET);
                    fread(next, sizeof(NK), 1, regf);
                    
                    // re-read it
                    int full_nk_size = sizeof(NK) + next->name_len - 1;
                    next = (NK *)realloc(next, full_nk_size);
                    fseek(regf, convOff(nk_offsets[i]), SEEK_SET);
                    fread(next, full_nk_size, 1, regf);
                    
                    printSubTree(next, regf, level+1);

                    free(next);
                }
                free(nk_offsets);

            }
            else {
                printf("Fatal: encountered unknown subentry of ri list\n");
                exit(1);
            }
        }
        free(li_offsets);
    }
    else {
        printf("Fatal: encountered unknown subkey type\n");
        exit(1);
    }
    return;
}

// Validate a hive header by checking its checksum and
// signature. Return value: 1 for valid, 0 for invalid.
int validHeader(HiveHeader *hdr) {
    if (strncmp(hdr->signature, "regf", 4)) {
        printf("Invalid header.\n");
        return 0;
    }

    uint32_t cksum = 0;
    uint32_t *cur = (uint32_t *) hdr;
    for (int i = 0; i < sizeof(HiveHeader)-4; i += 4) {
        cksum ^= *cur;
        cur++;
    }
    
    if (cksum != hdr->checksum) {
        printf("Bad checksum.\n");
        return 0;
    }

    return 1;
}

int main(int argc, char **argv) {
    
    if(argc < 2) {
        printf("Usage: %s <registry file>\n", argv[0]);
        exit(1);
    }

    FILE *regf;
    HiveHeader hdr;
    BlockHeader bh;

    regf = fopen(argv[1], "rb");
    
    if (!regf) {
        perror("fopen");
        exit(1);
    }

    // Read in the global header
    fread(&hdr, sizeof(HiveHeader), 1, regf);
    if(!validHeader(&hdr)) {
        printf("Registry file failed basic validation.\n");
        exit(1);
    }
    printNTTime(&hdr.modified);

    fseek(regf, 0x1000, SEEK_SET);
    fread(&bh, sizeof(BlockHeader), 1, regf);

    //printNTTime(&bh.modified);

    // find root nk cell
    int cell_size = -1;
    NK *root;
    while(1) {
        // If we're at a page boundary, see if we need to skip an hbin header
        // This should really never happen (the root key should be within the
        // first block), but better to be safe...
        if((ftell(regf) % 0x1000) == 0) {
            int32_t pos = ftell(regf);
            fread(&bh, sizeof(BlockHeader), 1, regf);
            if(strncmp(bh.signature,"hbin",4)) { // whoops, we were wrong, seek back
                fseek(regf, pos, SEEK_SET);
            }
        }
            
        fread(&cell_size, sizeof(int), 1, regf);

        // Haven't seen this documented anywhere: it appears that the cell size
        // is stored as a signed int and is -1 * the actual size. This is noted
        // in WinReg.txt, but the author there seems to indicate that this is
        // only the case for free blocks; this is clearly not the case here.
        int32_t cell_size_real = (-1*cell_size) - sizeof(int);
        if (cell_size_real < 0 || cell_size_real > 0x1000) exit(1);
        char *buf = (char*)malloc(cell_size_real);
        if (!buf) exit(1);
        fread(buf, cell_size_real, 1, regf);
        if(!strncmp(buf, "nk", 2)) {
            root = (NK *) buf;      
            if(root->type == NK_ROOT) {
                break;
            }
            else {
                free(buf);
            }
        }
    }

    printSubTree(root, regf, 0);

    fclose(regf);
    return 0;
}
