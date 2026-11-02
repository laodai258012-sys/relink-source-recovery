
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined * recovered_17c870(undefined8 param_1,undefined *param_2,longlong *param_3)

{
  code *pcVar1;
  int iVar2;
  undefined *puVar3;
  ulonglong uVar4;
  ulonglong uVar5;
  ulonglong uVar6;
  ulonglong uVar7;
  ulonglong uVar8;
  undefined8 uVar9;
  longlong lVar10;
  ulonglong in_stack_ffffffffffffff58;
  longlong *plStack_78;
  int iStack_70;
  undefined4 uStack_6c;
  longlong *plStack_68;
  int iStack_60;
  undefined4 uStack_5c;
  undefined8 uStack_58;
  undefined uStack_50;
  
  uVar8 = 0;
  uStack_58 = 0x142cc6b00;
  uStack_50 = 0;
  iVar2 = _Mtx_lock(0x142cc6b00);
  if (iVar2 != 0) {
    __Throw_Cpp_error_std__YAXH_Z(5);
    pcVar1 = (code *)swi(3);
    puVar3 = (undefined *)(*pcVar1)();
    return puVar3;
  }
  if (_DAT_142cc6b4c == 0x7fffffff) {
    _DAT_142cc6b4c = 0x7ffffffe;
    __Throw_Cpp_error_std__YAXH_Z(6);
    pcVar1 = (code *)swi(3);
    puVar3 = (undefined *)(*pcVar1)();
    return puVar3;
  }
  uStack_50 = 1;
  lVar10 = *param_3;
  if (lVar10 == param_3[1]) {
    if (_DAT_142d8ad80 == 0) {
      *param_2 = 1;
      param_2[0x20] = 5;
      goto LAB_14017c918;
    }
    iVar2 = (*_DAT_141ebd7b0)();
    lVar10 = (longlong)iVar2 + (_DAT_142d8ad80 - _DAT_142d8ad78);
  }
  else {
    uVar4 = (param_3[1] - lVar10 >> 3) * -0x3333333333333333;
    if (uVar4 < 2) {
      lVar10 = recovered_103ae0();
    }
    else {
      uVar5 = uVar8;
      if (6 < uVar4) {
        uVar5 = recovered_103ae0(lVar10 + 0xf0);
      }
      uVar4 = uVar8;
      if (5 < (ulonglong)((param_3[1] - *param_3 >> 3) * -0x3333333333333333)) {
        uVar4 = recovered_103ae0(*param_3 + 200);
      }
      in_stack_ffffffffffffff58 = uVar8;
      if (4 < (ulonglong)((param_3[1] - *param_3 >> 3) * -0x3333333333333333)) {
        in_stack_ffffffffffffff58 = recovered_103ae0(*param_3 + 0xa0);
      }
      uVar6 = uVar8;
      if (3 < (ulonglong)((param_3[1] - *param_3 >> 3) * -0x3333333333333333)) {
        uVar6 = recovered_103ae0(*param_3 + 0x78);
      }
      uVar7 = uVar8;
      if (2 < (ulonglong)((param_3[1] - *param_3 >> 3) * -0x3333333333333333)) {
        uVar7 = recovered_103ae0(*param_3 + 0x50);
      }
      if (1 < (ulonglong)((param_3[1] - *param_3 >> 3) * -0x3333333333333333)) {
        uVar8 = recovered_103ae0(*param_3 + 0x28);
      }
      uVar9 = recovered_103ae0(*param_3);
      lVar10 = recovered_177ad0(uVar9,uVar8,uVar7,uVar6,in_stack_ffffffffffffff58,uVar4,uVar5);
    }
    if (_DAT_142d8ad80 == 0) {
      _DAT_142d8ad80 = _Xtime_get_ticks();
      _DAT_142d8ad80 = _DAT_142d8ad80 / 10000;
      iVar2 = (*_DAT_141ebd7b0)();
      _DAT_142d8ad78 = (longlong)iVar2;
    }
  }
  plStack_78 = (longlong *)func_0x0001411ec250(8);
  *plStack_78 = lVar10;
  plStack_68 = (longlong *)
               (*_DAT_141ebd4f0)(0,0,&DAT_140191a00,plStack_78,
                                 in_stack_ffffffffffffff58 & 0xffffffff00000000,&iStack_60);
  if (plStack_68 != (longlong *)0x0) {
    if (iStack_60 != 0) {
      iStack_70 = iStack_60;
      uStack_6c = uStack_5c;
      plStack_78 = plStack_68;
      iVar2 = _Thrd_detach(&plStack_78);
      if (iVar2 == 0) {
        param_2[0x20] = 0;
LAB_14017c918:
        _Mtx_unlock(0x142cc6b00);
        return param_2;
      }
    }
    __Throw_Cpp_error_std__YAXH_Z(1);
  }
  iStack_60 = 0;
  __Throw_Cpp_error_std__YAXH_Z(6);
  pcVar1 = (code *)swi(3);
  puVar3 = (undefined *)(*pcVar1)();
  return puVar3;
}

