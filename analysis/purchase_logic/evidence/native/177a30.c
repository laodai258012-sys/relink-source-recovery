
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

longlong recovered_177a30(longlong param_1)

{
  int iVar1;
  longlong *plVar2;
  longlong lStackX_8;
  longlong lStackX_10;
  undefined auStackX_18 [16];
  undefined auStack_18 [16];
  
  if (0 < param_1) {
    recovered_c4ab0(&lStackX_10);
    lStackX_8 = param_1 * 10000 + 0x19db1ded53e8000;
    iVar1 = (*_DAT_141ebb618)(&lStackX_8,auStack_18);
    if (iVar1 != 0) {
      iVar1 = (*_DAT_141ebb630)(auStack_18);
      if (iVar1 != 0) {
        plVar2 = (longlong *)recovered_c4ab0(auStackX_18);
        return (*plVar2 - lStackX_10) / 1000000;
      }
    }
  }
  return -1;
}

