; NOTE: Assertions have been autogenerated by utils/update_mir_test_checks.py
; RUN: llc -mtriple=amdgcn-amd-amdhsa -mcpu=gfx908 -stop-after=finalize-isel -o - %s | FileCheck -check-prefix=GFX908 %s
; RUN: llc -mtriple=amdgcn-amd-amdhsa -mcpu=gfx90a -stop-after=finalize-isel -o - %s | FileCheck -check-prefix=GFX90A %s

; Make sure we only use one 128-bit register instead of 2 for i128 asm
; constraints

define amdgpu_kernel void @s_input_output_i128() {
  ; GFX908-LABEL: name: s_input_output_i128
  ; GFX908: bb.0 (%ir-block.0):
  ; GFX908-NEXT:   INLINEASM &"; def $0", 1 /* sideeffect attdialect */, 7208970 /* regdef:SGPR_128 */, def %13
  ; GFX908-NEXT:   [[COPY:%[0-9]+]]:sgpr_128 = COPY %13
  ; GFX908-NEXT:   INLINEASM &"; use $0", 1 /* sideeffect attdialect */, 7208969 /* reguse:SGPR_128 */, %14
  ; GFX908-NEXT:   S_ENDPGM 0
  ;
  ; GFX90A-LABEL: name: s_input_output_i128
  ; GFX90A: bb.0 (%ir-block.0):
  ; GFX90A-NEXT:   INLINEASM &"; def $0", 1 /* sideeffect attdialect */, 7208970 /* regdef:SGPR_128 */, def %11
  ; GFX90A-NEXT:   [[COPY:%[0-9]+]]:sgpr_128 = COPY %11
  ; GFX90A-NEXT:   INLINEASM &"; use $0", 1 /* sideeffect attdialect */, 7208969 /* reguse:SGPR_128 */, %12
  ; GFX90A-NEXT:   S_ENDPGM 0
  %val = tail call i128 asm sideeffect "; def $0", "=s"()
  call void asm sideeffect "; use $0", "s"(i128 %val)
  ret void
}

define amdgpu_kernel void @v_input_output_i128() {
  ; GFX908-LABEL: name: v_input_output_i128
  ; GFX908: bb.0 (%ir-block.0):
  ; GFX908-NEXT:   INLINEASM &"; def $0", 1 /* sideeffect attdialect */, 6094858 /* regdef:VReg_128 */, def %13
  ; GFX908-NEXT:   [[COPY:%[0-9]+]]:vreg_128 = COPY %13
  ; GFX908-NEXT:   INLINEASM &"; use $0", 1 /* sideeffect attdialect */, 6094857 /* reguse:VReg_128 */, %14
  ; GFX908-NEXT:   S_ENDPGM 0
  ;
  ; GFX90A-LABEL: name: v_input_output_i128
  ; GFX90A: bb.0 (%ir-block.0):
  ; GFX90A-NEXT:   INLINEASM &"; def $0", 1 /* sideeffect attdialect */, 6422538 /* regdef:VReg_128_Align2 */, def %11
  ; GFX90A-NEXT:   [[COPY:%[0-9]+]]:vreg_128_align2 = COPY %11
  ; GFX90A-NEXT:   INLINEASM &"; use $0", 1 /* sideeffect attdialect */, 6422537 /* reguse:VReg_128_Align2 */, %12
  ; GFX90A-NEXT:   S_ENDPGM 0
  %val = tail call i128 asm sideeffect "; def $0", "=v"()
  call void asm sideeffect "; use $0", "v"(i128 %val)
  ret void
}

define amdgpu_kernel void @a_input_output_i128() {
  ; GFX908-LABEL: name: a_input_output_i128
  ; GFX908: bb.0 (%ir-block.0):
  ; GFX908-NEXT:   INLINEASM &"; def $0", 1 /* sideeffect attdialect */, 6029322 /* regdef:AReg_128 */, def %13
  ; GFX908-NEXT:   [[COPY:%[0-9]+]]:areg_128 = COPY %13
  ; GFX908-NEXT:   INLINEASM &"; use $0", 1 /* sideeffect attdialect */, 6029321 /* reguse:AReg_128 */, %14

  ; GFX908-NEXT:   S_ENDPGM 0
  ;
  ; GFX90A-LABEL: name: a_input_output_i128
  ; GFX90A: bb.0 (%ir-block.0):
  ; GFX90A-NEXT:   INLINEASM &"; def $0", 1 /* sideeffect attdialect */, 6291466 /* regdef:AReg_128_Align2 */, def %11
  ; GFX90A-NEXT:   [[COPY:%[0-9]+]]:areg_128_align2 = COPY %11
  ; GFX90A-NEXT:   INLINEASM &"; use $0", 1 /* sideeffect attdialect */, 6291465 /* reguse:AReg_128_Align2 */, %12
  ; GFX90A-NEXT:   S_ENDPGM 0
  %val = call i128 asm sideeffect "; def $0", "=a"()
  call void asm sideeffect "; use $0", "a"(i128 %val)
  ret void
}
