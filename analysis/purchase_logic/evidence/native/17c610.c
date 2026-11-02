
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 * recovered_17c610(undefined8 param_1,undefined8 *param_2,longlong *param_3)

{
  code *pcVar1;
  int iVar2;
  undefined8 *puVar3;
  ulonglong uVar4;
  undefined8 uVar5;
  undefined8 uVar6;
  undefined8 uVar7;
  undefined8 uVar8;
  undefined8 uVar9;
  undefined8 uVar10;
  undefined8 uVar11;
  longlong lVar12;
  
  iVar2 = _Mtx_lock(0x142cc6b00);
  if (iVar2 != 0) {
    __Throw_Cpp_error_std__YAXH_Z(5);
    pcVar1 = (code *)swi(3);
    puVar3 = (undefined8 *)(*pcVar1)();
    return puVar3;
  }
  if (_DAT_142cc6b4c == 0x7fffffff) {
    _DAT_142cc6b4c = 0x7ffffffe;
    __Throw_Cpp_error_std__YAXH_Z(6);
    pcVar1 = (code *)swi(3);
    puVar3 = (undefined8 *)(*pcVar1)();
    return puVar3;
  }
  lVar12 = *param_3;
  if (lVar12 == param_3[1]) {
    if (_DAT_142d8ad80 == 0) {
      *(undefined *)param_2 = 1;
      *(undefined *)(param_2 + 4) = 5;
      goto LAB_14017c850;
    }
    iVar2 = (*_DAT_141ebd7b0)();
    lVar12 = (longlong)iVar2 + (_DAT_142d8ad80 - _DAT_142d8ad78);
  }
  else {
    uVar4 = (param_3[1] - lVar12 >> 3) * -0x3333333333333333;
    if (uVar4 < 2) {
      lVar12 = recovered_103ae0();
    }
    else {
      if (uVar4 < 7) {
        uVar11 = 0;
      }
      else {
        uVar11 = recovered_103ae0(lVar12 + 0xf0);
      }
      if ((ulonglong)((param_3[1] - *param_3 >> 3) * -0x3333333333333333) < 6) {
        uVar5 = 0;
      }
      else {
        uVar5 = recovered_103ae0(*param_3 + 200);
      }
      if ((ulonglong)((param_3[1] - *param_3 >> 3) * -0x3333333333333333) < 5) {
        uVar6 = 0;
      }
      else {
        uVar6 = recovered_103ae0(*param_3 + 0xa0);
      }
      if ((ulonglong)((param_3[1] - *param_3 >> 3) * -0x3333333333333333) < 4) {
        uVar7 = 0;
      }
      else {
        uVar7 = recovered_103ae0(*param_3 + 0x78);
      }
      if ((ulonglong)((param_3[1] - *param_3 >> 3) * -0x3333333333333333) < 3) {
        uVar8 = 0;
      }
      else {
        uVar8 = recovered_103ae0(*param_3 + 0x50);
      }
      if ((ulonglong)((param_3[1] - *param_3 >> 3) * -0x3333333333333333) < 2) {
        uVar9 = 0;
      }
      else {
        uVar9 = recovered_103ae0(*param_3 + 0x28);
      }
      uVar10 = recovered_103ae0(*param_3);
      lVar12 = recovered_177ad0(uVar10,uVar9,uVar8,uVar7,uVar6,uVar5,uVar11);
    }
    if (_DAT_142d8ad80 == 0) {
      _DAT_142d8ad80 = _Xtime_get_ticks();
      _DAT_142d8ad80 = _DAT_142d8ad80 / 10000;
      iVar2 = (*_DAT_141ebd7b0)();
      _DAT_142d8ad78 = (longlong)iVar2;
    }
  }
  uVar11 = recovered_177a30(lVar12);
  *param_2 = uVar11;
  *(undefined *)(param_2 + 4) = 1;
LAB_14017c850:
  _Mtx_unlock(0x142cc6b00);
  return param_2;
}

