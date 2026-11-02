
undefined (*) [16]
recovered_18c2d0(undefined (*param_1) [16],undefined8 param_2,undefined8 *param_3)

{
  undefined8 uVar1;
  
  *param_1 = ZEXT816(0);
  *(undefined8 *)param_1[1] = 0;
  *(undefined8 *)(param_1[1] + 8) = 0;
  recovered_87900(0,&UNK_1429f1710,0xc);
  uVar1 = *param_3;
  *param_3 = 0;
  *(undefined8 *)param_1[2] = uVar1;
  return param_1;
}

