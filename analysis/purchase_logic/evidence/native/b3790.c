
void recovered_b3790(longlong *param_1,longlong *param_2)

{
  int iVar1;
  code *pcVar2;
  longlong lVar3;
  ulonglong uVar4;
  longlong lVar5;
  ulonglong uVar6;
  longlong lVar7;
  longlong lVar8;
  ulonglong uVar9;
  undefined *puStack_1b8;
  undefined8 uStack_1b0;
  undefined4 uStack_1a8;
  undefined4 uStack_1a4;
  undefined auStack_1a0 [16];
  undefined8 uStack_190;
  undefined auStack_188 [16];
  longlong lStack_178;
  undefined auStack_170 [16];
  longlong lStack_160;
  undefined auStack_158 [264];
  undefined uStack_50;
  
  uVar6 = 0;
  lVar7 = *param_1;
  lVar5 = param_1[1];
  if (lVar7 != lVar5) {
    do {
      func_0x0001400b47e0(lVar7);
      lVar7 = lVar7 + 0x110;
    } while (lVar7 != lVar5);
    lVar7 = *param_1;
    param_1[1] = lVar7;
    lVar5 = lVar7;
  }
  lVar8 = param_2[1] - *param_2 >> 3;
  uVar9 = lVar8 * -0x71c71c71c71c71c7;
  lVar3 = param_1[2] - lVar7 >> 4;
  if ((ulonglong)(lVar3 * -0xf0f0f0f0f0f0f0f) <= uVar9 && uVar9 + lVar3 * 0xf0f0f0f0f0f0f0f != 0) {
    if (0xf0f0f0f0f0f0f0 < uVar9) {
      func_0x0001400b6800();
      pcVar2 = (code *)swi(3);
      (*pcVar2)();
      return;
    }
    uVar4 = lVar8 * 0x1c71c71c71c71c90;
    if (uVar4 != 0) {
      if (uVar4 < 0x1000) {
        uVar6 = func_0x0001411ec250();
      }
      else {
        if (uVar4 + 0x27 <= uVar4) {
          recovered_82b80();
          pcVar2 = (code *)swi(3);
          (*pcVar2)();
          return;
        }
        lVar3 = func_0x0001411ec250(uVar4 + 0x27);
        if (lVar3 == 0) {
LAB_1400b3ab5:
          pcVar2 = (code *)swi(0x29);
          (*pcVar2)(5);
          return;
        }
        uVar6 = lVar3 + 0x27U & 0xffffffffffffffe0;
        *(longlong *)(uVar6 - 8) = lVar3;
      }
    }
    func_0x0001400b6d40(*param_1,param_1[1],uVar6,param_1);
    func_0x0001400b7b70(param_1,uVar6,(lVar5 - lVar7 >> 4) * -0xf0f0f0f0f0f0f0f,uVar9);
  }
  lVar7 = param_2[1];
  do {
    if (lVar7 == *param_2) {
      return;
    }
    puStack_1b8 = &UNK_1428e9738;
    uStack_1b0 = 0;
    uStack_1a8 = 0xffffffff;
    uStack_1a4 = 0;
    auStack_1a0 = ZEXT816(0);
    uStack_190 = 0;
    auStack_188 = ZEXT816(0);
    lStack_178 = 0;
    auStack_170 = ZEXT816(0);
    lStack_160 = 0;
    func_0x0001400bb280(auStack_158,&puStack_1b8);
    uStack_50 = 0;
    lVar5 = auStack_170._0_8_;
    if (auStack_170._0_8_ != 0) {
      lVar8 = auStack_170._8_8_;
      for (lVar3 = auStack_170._0_8_; lVar3 != lVar8; lVar3 = lVar3 + 0x110) {
        func_0x0001400b47e0(lVar3);
      }
      uVar6 = (lStack_160 - lVar5 >> 4) * 0x10;
      if (0xfff < uVar6) {
        if (0x1f < (lVar5 - *(longlong *)(lVar5 + -8)) - 8U) goto LAB_1400b3ab5;
        uVar6 = uVar6 + 0x27;
        lVar5 = *(longlong *)(lVar5 + -8);
      }
      func_0x0001411ec560(lVar5,uVar6);
    }
    lVar5 = auStack_188._0_8_;
    if (auStack_188._0_8_ != 0) {
      lVar8 = auStack_188._8_8_;
      for (lVar3 = auStack_188._0_8_; lVar3 != lVar8; lVar3 = lVar3 + 0x110) {
        func_0x0001400b47e0(lVar3);
      }
      uVar6 = (lStack_178 - lVar5 >> 4) * 0x10;
      if (0xfff < uVar6) {
        if (0x1f < (lVar5 - *(longlong *)(lVar5 + -8)) - 8U) goto LAB_1400b3ab5;
        uVar6 = uVar6 + 0x27;
        lVar5 = *(longlong *)(lVar5 + -8);
      }
      func_0x0001411ec560(lVar5,uVar6);
    }
    if ((int *)auStack_1a0._0_8_ != (int *)0x0) {
      LOCK();
      iVar1 = *(int *)auStack_1a0._0_8_;
      *(int *)auStack_1a0._0_8_ = *(int *)auStack_1a0._0_8_ + -1;
      UNLOCK();
      if (iVar1 == 1) {
        func_0x000140f82460(auStack_1a0._0_8_,2,8);
      }
    }
    if (*(char *)(lVar7 + -8) == '\x02') {
      recovered_87a20(&puStack_1b8,lVar7 + -0x48);
    }
    else {
      func_0x0001400b5330(&puStack_1b8);
    }
    recovered_b07e0(auStack_158,&puStack_1b8);
    func_0x0001400b5230(auStack_1a0);
    func_0x0001400b52a0(&uStack_1b0);
    lVar5 = param_1[1];
    if (lVar5 == param_1[2]) {
      func_0x0001400b9000(param_1,lVar5,auStack_158);
    }
    else {
      func_0x0001400bad20(lVar5,auStack_158);
      param_1[1] = param_1[1] + 0x110;
    }
    func_0x0001400b47e0(auStack_158);
    lVar7 = lVar7 + -0x48;
  } while( true );
}

