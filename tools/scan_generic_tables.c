/* 7.1 generic-table structural scanner (R22 evidence tool).
 * Scans a metadata blob for standard-layout Il2CppGenericContainer (16B) and
 * Il2CppGenericParameter (14B) runs. See docs/re/71-generics-interface-origin.md.
 * Build: gcc -O2 -o /tmp/scan_generic_tables tools/scan_generic_tables.c
 * Run on: body (= global-metadata.dat[0x210..]) and startup-metadata.dat
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static uint8_t *buf; static size_t n;
static uint32_t U32(size_t o){ return (uint32_t)buf[o] | ((uint32_t)buf[o+1]<<8) | ((uint32_t)buf[o+2]<<16) | ((uint32_t)buf[o+3]<<24); }
static uint16_t U16(size_t o){ return (uint16_t)(buf[o] | (buf[o+1]<<8)); }

int main(int argc,char**argv){
  if(argc<2){fprintf(stderr,"usage: %s file\n",argv[0]);return 1;}
  FILE*f=fopen(argv[1],"rb"); fseek(f,0,SEEK_END); n=ftell(f); fseek(f,0,SEEK_SET);
  buf=malloc(n); fread(buf,1,n,f); fclose(f);
  printf("size %zu\n", n);
  // 1) generic containers: 16B rows {owner, argc, is_method, param_start}, param_start cumulative
  size_t found=0;
  for(size_t o=0; o+16*64 < n; o+=4){
    uint32_t owner=U32(o), arg=U32(o+4), ism=U32(o+8), ps=U32(o+12);
    if(ism>1 || arg<1 || arg>16 || owner>=733481 || ps>60000) continue;
    if(ism==0 && owner>=88902) continue;
    int ok=1; uint32_t cp=ps, co=owner, cm=ism;
    for(int k=1;k<64;k++){
      size_t q=o+16*(size_t)k; if(q+16>n){ok=0;break;}
      uint32_t ow=U32(q), ar=U32(q+4), im=U32(q+8), p=U32(q+12);
      if(im>1 || ar<1 || ar>16 || p!=cp+arg || ow>co+4096 || (im==0&&ow>=88902) || ow>=733481){ok=0;break;}
      cp=p; co=ow; cm=im; arg=ar;
    }
    if(ok){ printf("CONTAINERS candidate off=0x%zx owner0=%u argc0=%u ism0=%u ps0=%u\n", o, owner, U32(o+4), ism, ps); if(++found>10) break; }
  }
  // 2) generic parameters: 14B rows {nameIdx, cStart(u16), cCount(u16), owner, flags(u16)}
  size_t found2=0;
  for(size_t o=0; o+14*48 < n; o+=4){
    uint32_t ni=U32(o); uint16_t cs=U16(o+4), cc=U16(o+6); uint32_t ow=U32(o+8); uint16_t fl=U16(o+12);
    if((ni>>24)>31 || (ni&0xFFFFFF)>=0x1300000 || cs>0x2000 || cc>0x200 || ow>=733481 || fl>0x100) continue;
    int ok=1; uint32_t prev=cs;
    for(int k=1;k<48;k++){
      size_t q=o+14*(size_t)k; if(q+14>n){ok=0;break;}
      uint32_t ni2=U32(q); uint16_t cs2=U16(q+4), cc2=U16(q+6); uint32_t ow2=U32(q+8); uint16_t fl2=U16(q+12);
      if((ni2>>24)>31 || (ni2&0xFFFFFF)>=0x1300000 || cs2<prev || cs2>0x2000 || cc2>0x200 || ow2>=733481 || fl2>0x100){ok=0;break;}
      prev=cs2;
    }
    if(ok){ printf("GENERICPARAM candidate off=0x%zx name0=0x%x cStart0=%u owner0=%u flags0=%u\n", o, ni, cs, ow, fl); if(++found2>10) break; }
  }
  printf("found containers=%zu genericparams=%zu\n", found, found2);
  return 0;
}
