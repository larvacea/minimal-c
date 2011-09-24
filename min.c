#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <unistd.h>
#include <checkint.h>

static unsigned long long syspp_wc = 0;
static unsigned long long syspp_width = 132;
static unsigned long long syspp_lpp = 0;
static FILE *disasm_file = NULL;

static void print_code(FILE *f, const unsigned long long *min_mem, unsigned long long pointer);
static void print_pattern(FILE *f, const unsigned long long *min_mem, unsigned long long pointer, int indent);
static void bad_lct(void)

{
  fprintf(stderr, "Bad LCT!\n");
  exit(0);
}

#include "min_code.h"

 SYSID:
  XR = HEADER_LINE;
  XL = SUBHEAD;
  goto *SYSID_return;
 SYSPI:
  fwrite((FILE *) min_mem[XR+2], 1, WA, stdout);
  EXI_CODE = 0;
  goto *SYSPI_return;
 SYSPP:
  WA = syspp_width;
  WB = syspp_lpp;
  WC = syspp_wc;
  goto *SYSPP_return;
 SYSIO:
  if (!WA) {
    printf("Oh noes, no FCBLK!\n");
    exit(0);
  }
  min_mem[--XS] = *((char *) (min_mem + XL + 2) + min_mem[XL+1]);
  *((char *) (min_mem + XL + 2) + min_mem[XL+1]) = 0;
  if (WB) { // output
    if (!(min_mem[WA+2] = (unsigned long long) fopen((char *) (min_mem+XL+2), "w"))) EXI_CODE = 1;
    else EXI_CODE = 0;
  }
  else { // input
    if (!(min_mem[WA+2] = (unsigned long long) fopen((char *) (min_mem+XL+2), "r"))) EXI_CODE = 1;
    else EXI_CODE = 0;
  }
  *((char *) (min_mem + XL + 2) + min_mem[XL+1]) = min_mem[XS++];
  XL = WA;
  WC = 0;
  goto *SYSIO_return;
 SYSFC:
  XS += WC; // pop off SCBLKs from the stack
  EXI_CODE = 0; // success
  WA = 3; // 3 words for FCBLK
  XL = 0;
  WC = 1;  // FCBLK is XNBLK
  goto *SYSFC_return;
 SYSGC:
  goto *SYSGC_return;
 SYSDM:
  goto *SYSDM_return;
 SYSOU:
  fwrite(min_mem+XR+2, min_mem[XR+1], 1, (FILE *) min_mem[WA+2]);
  fputc('\n', (FILE *) min_mem[WA+2]);
  EXI_CODE = 0;
  goto *SYSOU_return;
 SYSRI:
  EXI_CODE = 1;
  goto *SYSRI_return;
 SYSIL:
  if (WA) {
    WA = 16384;
    WC = 1;
  }
  else {
    WA = 0;
    WC = 1;
  }
  goto *SYSIL_return;
 SYSIN:
  if (WA) {
    EXI_CODE = 0;
    if (!fgets((char *) (min_mem+XR+2), min_mem[XR+1], (FILE *) min_mem[WA+2])) EXI_CODE = 1;
    else {
      min_mem[XR+1] = strlen((char *) (min_mem+XR+2));
      if (*((char *) (min_mem+XR+2) + min_mem[XR+1] - 1) == '\n') min_mem[XR+1]--;
      if (*((char *) (min_mem+XR+2) + min_mem[XR+1] - 1) == '\r') min_mem[XR+1]--;
    }
  }
  else
    EXI_CODE = 1;
  goto *SYSIN_return;
 SYSRD:
  if (feof(stdin)) {
    EXI_CODE = 1;
    goto *SYSRD_return;
  }
  if (!fgets((char *) (min_mem+XR+2), WC, stdin)) {
    EXI_CODE = 1;
    goto *SYSRD_return;
  }
  min_mem[XR+1] = strlen((char *) (min_mem+XR+2));
  if (*((char *) (min_mem+XR+2) + min_mem[XR+1] - 1) == '\n') min_mem[XR+1]--;
  if (*((char *) (min_mem+XR+2) + min_mem[XR+1] - 1) == '\r') min_mem[XR+1]--;
  EXI_CODE = 0;
  goto *SYSRD_return;
 SYSTT:
  EXI_CODE = 0;
  goto *SYSTT_return;
 SYSST:
  EXI_CODE = 4;
  goto *SYSST_return;
 SYSRW:
  if (!WA) {
    EXI_CODE = 1;
    goto *SYSRW_return;
  }
  rewind((FILE *) min_mem[WA+2]);
  EXI_CODE = 0;
  goto *SYSRW_return;
 SYSHS:
  EXI_CODE = 5;
  XR = SYSHS_STRING;
  goto *SYSHS_return;
 SYSXI:
  EXI_CODE = 1;
  goto *SYSXI_return;
 SYSEN:
  EXI_CODE = 2;
  goto *SYSEN_return;
 SYSEP:
  printf("\n");
  EXI_CODE = 0;
  goto *SYSEP_return;
 SYSEF:
  if (!WA) {
    EXI_CODE = 1;
    goto *SYSEF_return;
  }
  fprintf((FILE *) min_mem[WA+2], "\n");
  EXI_CODE = 0;
  goto *SYSEF_return;
 SYSDT:
  time(&tloc);
  strncpy((char *) (min_mem+DATE_STRING+2), ctime(&tloc), 26);
  XL = DATE_STRING;
  min_mem[DATE_STRING+1] = 24;
  EXI_CODE = 0;
  goto *SYSDT_return;
 SYSAX:
  EXI_CODE = 0;
  goto *SYSAX_return;
 SYSBX:
  EXI_CODE = 0;
  if (disasm_file)
    print_code(disasm_file, min_mem, min_mem[1339]);
  goto *SYSBX_return;
 SYSCR:
  WA = snprintf(syscr_buffer, sizeof(syscr_buffer), "%.*LG", (int) WA, RA);
  if (WA > sizeof(syscr_buffer))
    WA = sizeof(syscr_buffer);
  if (WA > WC) {
    memcpy((char *) (min_mem + XR + 2), syscr_buffer, WC);
    WA = WC;
  }
  else {
    memcpy((char *) (min_mem + XR + 2), syscr_buffer, WA);
  }
  EXI_CODE = 0;
  goto *SYSCR_return;
 SYSDC:
  EXI_CODE = 0;
  goto *SYSDC_return;
 SYSEJ:
  exit(WB);
 SYSPR:
  fwrite(min_mem+XR+2,WA,1,stdout);
  printf("\n");
  EXI_CODE = 0;
  goto *SYSPR_return;
 SYSMM:
  memory_size += 1024*1024*1024;
  min_mem = realloc(min_mem, memory_size);
  XR = 1024*1024*1024;
  EXI_CODE = 0;
  goto *SYSMM_return;
 SYSMX:
  WA = 0;
  EXI_CODE = 0;
  goto *SYSMX_return;
 SYSTM:
  IA = (clock()*1000)/CLOCKS_PER_SEC;
  EXI_CODE = 0;
  goto *SYSTM_return;
 CALL_STACK_OVERFLOW:
  fprintf(stderr, "Call stack overflow.");
  exit(0);
}

static void print_vrblk(FILE * f, const unsigned long long *min_mem, unsigned long long vrblk)

{
  if (min_mem[vrblk+7]) {
    fprintf(f, "%.*s", (int) min_mem[vrblk+7], (char *) (min_mem+vrblk+8));
  }
  else {
    fprintf(f, "sv(%.*s)", (int) min_mem[1+min_mem[vrblk+8]], (char *) (min_mem+2+min_mem[vrblk+8]));
  }
}

static void print_code(FILE * f, const unsigned long long *min_mem, unsigned long long pointer)

{
  unsigned long long *thingy, *new_thingy;
  unsigned long long thingy_size = 1024;
  unsigned long long cp, p;
  unsigned long long stack[512];
  unsigned long long stacked_by[512];
  unsigned long long sp = 512;
  unsigned long long op;
  unsigned long long deepest = 512;
  thingy = calloc(thingy_size, sizeof(*thingy));

  for (p = min_mem[hash_HSHTB]; p < min_mem[hash_HSHTE]; ++p) {
    for (cp = min_mem[p]; cp; cp = min_mem[6+cp]) {
      if (min_mem[min_mem[cp+4]] != ent_loc_L_UND) {
	fprintf(f, "label ");
	print_vrblk(f, min_mem, cp);
	if (min_mem[cp+7]) {
	  fprintf(f, " (%llu)", min_mem[cp+4]);
	  if (sp) {
	    stack[--sp] = min_mem[cp+4];
	    stacked_by[sp] = cp;
	  }
	}
	fprintf(f, "\n");
      }
      if (min_mem[min_mem[cp+5]] != ent_loc_O_FUN) {
	fprintf(f, "function ");
	print_vrblk(f, min_mem, cp);
	fprintf(f, "\n");
      }
    }
  }
  deepest = sp;
  p = pointer;
  do {
    if (p > 30000) {
      if (min_mem[p+1] >= thingy_size) {
	thingy = realloc(thingy, (100+min_mem[p+1])*sizeof(*thingy));
	thingy_size = 100+min_mem[p+1];
      }
      if (!thingy[min_mem[p+1]]) {
	fprintf(f, "%llu: %llu\n", p, min_mem[p+1]);
	thingy[min_mem[p+1]] = p;
	op = min_mem[min_mem[p+3]];
	if (op == ent_loc_B_VRG) {
	  if (sp && min_mem[min_mem[min_mem[p+3]+1]] != ent_loc_L_UND) {
	    stack[--sp] = min_mem[min_mem[p+3]+1];
	    stacked_by[sp] = p;
	  }
	}
	if (op == ent_loc_B_CDS) {
	  if (sp && min_mem[min_mem[p+3]] != ent_loc_L_UND) {
	    stack[--sp] = min_mem[p+3];
	    stacked_by[sp] = p;
	  }
	}
	if (ent_loc_B_CDS == min_mem[min_mem[p+min_mem[p+2]-1]]) {
	  if (sp && min_mem[min_mem[p+min_mem[p+2]-1]] != ent_loc_L_UND) {
	    stack[--sp] = min_mem[p+min_mem[p+2]-1];
	    stacked_by[sp] = p;
	  }
	}
	else if (ent_loc_B_VRG == min_mem[min_mem[p+min_mem[p+2]-1]]) {
	  if (sp && min_mem[min_mem[1+min_mem[p+min_mem[p+2]-1]]] != ent_loc_L_UND) {
	    stack[--sp] = min_mem[1+min_mem[p+min_mem[p+2]-1]];
	    stacked_by[sp] = p;
	  }
	}
      }
    }
    else fprintf(f, "%llu: Bogus (stacked by %llu)\n", p, stacked_by[sp-1]);
    fprintf(f, "Depth %llu\n", 512 - sp);
    if (sp < deepest) deepest = sp;
    if (sp < 512) {
      p = stack[sp++];
    }
    else break;
  } while (1);
  fprintf(f, "Maximum depth %llu\n", 512ull - deepest);
  
  for (sp = 1; sp < thingy_size; sp++) {
    p = thingy[sp];
    if (p) {
      fprintf(f, "CDJMP: %s\n", (char *) min_mem[min_mem[p]+2]);
      fprintf(f, "CDFAL: %llu: %s", min_mem[p+3], (char *) min_mem[min_mem[min_mem[p+3]]+2]);
      switch (min_mem[min_mem[p+3]]) {
      case ent_loc_B_VRG:
	fprintf(f, " -> %llu (", min_mem[1+min_mem[p+3]]);
	print_vrblk(f, min_mem, min_mem[p+3]-3);
	fprintf(f, ")\n");
	break;
      case ent_loc_B_CDS:
	fprintf(f, " statement %llu\n", min_mem[1+min_mem[p+3]]);
	break;
      default:
	fprintf(f, "\n");
	break;
      }
      fprintf(f, "Statement %llu\n", min_mem[p+1]);
      if (min_mem[p+1] >= thingy_size) {
	thingy = realloc(thingy, (min_mem[p+1]+100)*sizeof(*thingy));
      }
      fprintf(f, "Length %llu\n", min_mem[p+2]);
      for (cp = p+4; cp < p+min_mem[p+2]; cp++) {
	fprintf(f, "  %llu: %s", min_mem[cp], (char *) min_mem[2+min_mem[min_mem[cp]]]);
	op = min_mem[min_mem[cp]];
	switch (op) {
	case ent_loc_B_CDS:
	  fprintf(f, " statement %llu\n", min_mem[1+min_mem[cp]]);
	  break;
	case ent_loc_B_SCL:
	  fprintf(f, " \"%.*s\"\n", (int) min_mem[1+min_mem[cp]], (char *) (min_mem+2+min_mem[cp]));
	  break;
	case ent_loc_B_VRS:
	  fprintf(f, " ");
	  print_vrblk(f, min_mem, min_mem[cp]-1);
	  fprintf(f, "\n");
	  break;
	case ent_loc_B_VRL:
	  fprintf(f, " ");
	  print_vrblk(f, min_mem, min_mem[cp]);
	  fprintf(f, "\n");
	  break;
	case ent_loc_B_ICL:
	  fprintf(f, " (%llu)\n", min_mem[1+min_mem[cp]]);
	  break;
	case ent_loc_B_VRG:
	  fprintf(f, " -> %llu (", min_mem[1+min_mem[cp]]);
	  print_vrblk(f, min_mem, min_mem[cp]-3);
	  fprintf(f, ")\n");
	  break;
	case ent_loc_O_AON:
	  fprintf(f, " array, one subscript, by name\n");
	  break;
	case ent_loc_O_FNC:
	  fprintf(f, "  args: %llu, func: ", min_mem[cp+1]);
	  print_vrblk(f, min_mem, min_mem[cp+2]);
	  fprintf(f, "\n");
	  cp += 2;
	  break;
	case ent_loc_O_FNS:
	  fprintf(f, "  function, one arg: ");
	  print_vrblk(f, min_mem, min_mem[cp+1]);
	  fprintf(f, "\n");
	  cp += 1;
	  break;
	case ent_loc_O_LVN:
	  fprintf(f, " var: ");
	  print_vrblk(f, min_mem, min_mem[++cp]);
	  fprintf(f, "\n");
	  break;
	case ent_loc_O_LPT:
	  fprintf(f, "\n*** Pattern ***\n");
	  print_pattern(f, min_mem,min_mem[cp+1],2);
	  fprintf(f, "*** End Pattern ***\n");
	  cp++;
	  break;
	default:
	  fprintf(f, "\n");
	  break;
	}
      }
    }
  }
}

static void print_pattern(FILE * f, const unsigned long long *min_mem, unsigned long long pointer, int indent)

{
  do {
    if (min_mem[pointer] == ent_loc_P_NTH) {
      fprintf(f, "%*.s%llu: P$NTH\n", indent, "", pointer);
      return;
    }
    fprintf(f, "%*.s%llu: %s -> %llu", indent, "", pointer, (char *) min_mem[2+min_mem[pointer]], min_mem[pointer+1]);
    switch (min_mem[pointer]) {
    case ent_loc_P_ALT:
      fprintf(f, " alt: %llu\n", min_mem[pointer+2]);
      print_pattern(f, min_mem, min_mem[pointer+2], indent + 2);
      break;
    case ent_loc_P_ANS:
      fprintf(f, " any('%c')\n", (char) min_mem[pointer+2]);
      break;
    case ent_loc_P_BKS:
      fprintf(f, " break('%c')\n", (char) min_mem[pointer+2]);
      break;
    case ent_loc_P_LEN:
      fprintf(f, " len(%llu)\n", min_mem[pointer+2]);
      break;
    case ent_loc_P_PAC:
      if (min_mem[min_mem[pointer+2]] == ent_loc_B_VRL) {
	fprintf(f, " ");
	print_vrblk(f, min_mem,min_mem[pointer+2]);
	fprintf(f, "\n");
      }
      else
	fprintf(f, " unknown block type %s\n", (char *) min_mem[2+min_mem[pointer+2]]);
      break;
    case ent_loc_P_POS:
      fprintf(f, " pos(%llu)\n", min_mem[pointer+2]);
      break;
    case ent_loc_P_RTB:
      fprintf(f, " rtab(%llu)\n", min_mem[pointer+2]);
      break;
    case ent_loc_P_SPS:
      fprintf(f, " span('%c')\n", (char) min_mem[pointer+2]);
      break;
    case ent_loc_P_STR:
      fprintf(f, " \"%.*s\"\n", (int) min_mem[1+min_mem[pointer+2]], (char *) (min_mem+2+min_mem[pointer+2]));
      break;
    default:
      fprintf(f, "\n");
      break;
    }
    pointer = min_mem[pointer+1];
  } while (1);
}

static void usage(const char *name)
{
  fprintf(stderr, "Usage: %s -e -l# -s -r -x -h -c -p -n\n", name);
  fprintf(stderr, "  -e send error messages to stderr\n");
  fprintf(stderr, "  -f# listing format:  0 = compact, 1 = standard, 2 = extended\n");
  fprintf(stderr, "  -s suppress compilation statistics\n");
  fprintf(stderr, "  -r suppress execution statistics\n");
  fprintf(stderr, "  -x suppress execution\n");
  fprintf(stderr, "  -h suppress headers\n");
  fprintf(stderr, "  -c fold case, lower to upper\n");
  fprintf(stderr, "  -p print control cards\n");
  fprintf(stderr, "  -n do not execute if there are compilation errors\n");
  fprintf(stderr, "  -w# output width\n");
  fprintf(stderr, "  -l# lines per page\n");
  exit(0);
}

int main(int argc, char **argv)

{
  int ch;
  int format;

  while ((ch = getopt(argc, argv, "ef:srxhcpnw:l:d:")) != -1) {
    switch (ch) {
    case 'd':
      disasm_file = fopen(optarg, "w");
      break;
    case 'e':
      syspp_wc |= 0x1ll;
      break;
    case 'f':
      if (!sscanf(optarg, "%i", &format)) usage(argv[0]);
      switch (format) {
      case 0:
	syspp_wc &= ~(0x20ll | 0x100ll);
	break;
      case 1:
	syspp_wc &= ~0x20ll;
	syspp_wc |= 0x100ll;
	break;
      case 2:
	syspp_wc |= 0x20ll;
	break;
      default:
	usage(argv[0]);
	break;
      }
      break;
    case 's':
      syspp_wc |= 0x8ll;
      break;
    case 'r':
      syspp_wc |= 0x10ll;
      break;
    case 'x':
      syspp_wc |= 0x40ll;
      break;
    case 'h':
      syspp_wc |= 0x200ll;
      break;
    case 'c':
      syspp_wc |= 0x1000ll;
      break;
    case 'p':
      syspp_wc |= 0x400ll;
      break;
    case 'n':
      syspp_wc |= 0x800ll;
      break;
    case 'w':
      if (!sscanf(optarg, "%llu", &syspp_width)) usage(argv[0]);
      break;
    case 'l':
      if (!sscanf(optarg, "%llu", &syspp_lpp)) usage(argv[0]);
      break;
    default:
      usage(argv[0]);
      break;
    }
  }
  minimal_code();
}
