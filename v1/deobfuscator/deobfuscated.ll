; ModuleID = ""
target triple = "x86-64-pc-linux-gnu"
target datalayout = ""

define i64 @"deobfuscated"(i32 %"SymVar_0", i32 %"SymVar_1") nounwind
{
.4:
  %".5" = zext i32 %"SymVar_0" to i64
  %".6" = trunc i64 %".5" to i32
  %".7" = trunc i32 %".6" to i8
  %".8" = zext i8 %".7" to i64
  %".9" = trunc i64 %".5" to i32
  %".10" = lshr i32 %".9", 8
  %".11" = trunc i32 %".10" to i8
  %".12" = zext i8 %".11" to i64
  %".13" = shl i64 %".12", 8
  %".14" = or i64 %".8", %".13"
  %".15" = trunc i64 %".5" to i32
  %".16" = lshr i32 %".15", 16
  %".17" = trunc i32 %".16" to i8
  %".18" = zext i8 %".17" to i64
  %".19" = shl i64 %".18", 16
  %".20" = or i64 %".14", %".19"
  %".21" = trunc i64 %".5" to i32
  %".22" = lshr i32 %".21", 24
  %".23" = trunc i32 %".22" to i8
  %".24" = zext i8 %".23" to i64
  %".25" = shl i64 %".24", 24
  %".26" = or i64 %".20", %".25"
  %".27" = zext i8 0 to i64
  %".28" = shl i64 %".27", 32
  %".29" = or i64 %".26", %".28"
  %".30" = zext i8 0 to i64
  %".31" = shl i64 %".30", 40
  %".32" = or i64 %".29", %".31"
  %".33" = zext i8 0 to i64
  %".34" = shl i64 %".33", 48
  %".35" = or i64 %".32", %".34"
  %".36" = zext i8 0 to i64
  %".37" = shl i64 %".36", 56
  %".38" = or i64 %".35", %".37"
  %".39" = trunc i64 %".38" to i8
  %".40" = zext i8 %".39" to i32
  %".41" = lshr i64 %".38", 8
  %".42" = trunc i64 %".41" to i8
  %".43" = zext i8 %".42" to i32
  %".44" = shl i32 %".43", 8
  %".45" = or i32 %".40", %".44"
  %".46" = lshr i64 %".38", 16
  %".47" = trunc i64 %".46" to i8
  %".48" = zext i8 %".47" to i32
  %".49" = shl i32 %".48", 16
  %".50" = or i32 %".45", %".49"
  %".51" = lshr i64 %".38", 24
  %".52" = trunc i64 %".51" to i8
  %".53" = zext i8 %".52" to i32
  %".54" = shl i32 %".53", 24
  %".55" = or i32 %".50", %".54"
  %".56" = sext i32 %".55" to i64
  %".57" = trunc i64 %".56" to i32
  %".58" = zext i32 %".57" to i64
  %".59" = trunc i64 %".58" to i32
  %".60" = sext i32 %".59" to i64
  %".61" = trunc i64 %".60" to i32
  %".62" = zext i32 %".61" to i64
  %".63" = trunc i64 %".62" to i32
  %".64" = sext i32 %".63" to i64
  %".65" = trunc i64 %".64" to i32
  %".66" = zext i32 %".65" to i64
  %".67" = trunc i64 %".66" to i32
  %".68" = sext i32 %".67" to i64
  %".69" = trunc i64 %".68" to i32
  %".70" = zext i32 %".69" to i64
  %".71" = trunc i64 %".70" to i32
  %".72" = sext i32 %".71" to i64
  %".73" = zext i32 %"SymVar_1" to i64
  %".74" = trunc i64 %".73" to i32
  %".75" = trunc i32 %".74" to i8
  %".76" = zext i8 %".75" to i64
  %".77" = trunc i64 %".73" to i32
  %".78" = lshr i32 %".77", 8
  %".79" = trunc i32 %".78" to i8
  %".80" = zext i8 %".79" to i64
  %".81" = shl i64 %".80", 8
  %".82" = or i64 %".76", %".81"
  %".83" = trunc i64 %".73" to i32
  %".84" = lshr i32 %".83", 16
  %".85" = trunc i32 %".84" to i8
  %".86" = zext i8 %".85" to i64
  %".87" = shl i64 %".86", 16
  %".88" = or i64 %".82", %".87"
  %".89" = trunc i64 %".73" to i32
  %".90" = lshr i32 %".89", 24
  %".91" = trunc i32 %".90" to i8
  %".92" = zext i8 %".91" to i64
  %".93" = shl i64 %".92", 24
  %".94" = or i64 %".88", %".93"
  %".95" = zext i8 %".7" to i64
  %".96" = shl i64 %".95", 32
  %".97" = or i64 %".94", %".96"
  %".98" = zext i8 %".11" to i64
  %".99" = shl i64 %".98", 40
  %".100" = or i64 %".97", %".99"
  %".101" = zext i8 %".17" to i64
  %".102" = shl i64 %".101", 48
  %".103" = or i64 %".100", %".102"
  %".104" = zext i8 %".23" to i64
  %".105" = shl i64 %".104", 56
  %".106" = or i64 %".103", %".105"
  %".107" = trunc i64 %".106" to i8
  %".108" = zext i8 %".107" to i32
  %".109" = lshr i64 %".106", 8
  %".110" = trunc i64 %".109" to i8
  %".111" = zext i8 %".110" to i32
  %".112" = shl i32 %".111", 8
  %".113" = or i32 %".108", %".112"
  %".114" = lshr i64 %".106", 16
  %".115" = trunc i64 %".114" to i8
  %".116" = zext i8 %".115" to i32
  %".117" = shl i32 %".116", 16
  %".118" = or i32 %".113", %".117"
  %".119" = lshr i64 %".106", 24
  %".120" = trunc i64 %".119" to i8
  %".121" = zext i8 %".120" to i32
  %".122" = shl i32 %".121", 24
  %".123" = or i32 %".118", %".122"
  %".124" = sext i32 %".123" to i64
  %".125" = trunc i64 %".124" to i32
  %".126" = zext i32 %".125" to i64
  %".127" = trunc i64 %".126" to i32
  %".128" = sext i32 %".127" to i64
  %".129" = trunc i64 %".128" to i32
  %".130" = zext i32 %".129" to i64
  %".131" = trunc i64 %".130" to i32
  %".132" = sext i32 %".131" to i64
  %".133" = trunc i64 %".132" to i32
  %".134" = zext i32 %".133" to i64
  %".135" = trunc i64 %".134" to i32
  %".136" = sext i32 %".135" to i64
  %".137" = xor i64 %".72", %".136"
  %".138" = trunc i64 %".137" to i32
  %".139" = zext i32 %".138" to i64
  %".140" = trunc i64 %".139" to i32
  %".141" = trunc i32 %".140" to i8
  %".142" = zext i8 %".141" to i64
  %".143" = trunc i64 %".139" to i32
  %".144" = lshr i32 %".143", 8
  %".145" = trunc i32 %".144" to i8
  %".146" = zext i8 %".145" to i64
  %".147" = shl i64 %".146", 8
  %".148" = or i64 %".142", %".147"
  %".149" = trunc i64 %".139" to i32
  %".150" = lshr i32 %".149", 16
  %".151" = trunc i32 %".150" to i8
  %".152" = zext i8 %".151" to i64
  %".153" = shl i64 %".152", 16
  %".154" = or i64 %".148", %".153"
  %".155" = trunc i64 %".139" to i32
  %".156" = lshr i32 %".155", 24
  %".157" = trunc i32 %".156" to i8
  %".158" = zext i8 %".157" to i64
  %".159" = shl i64 %".158", 24
  %".160" = or i64 %".154", %".159"
  %".161" = zext i8 0 to i64
  %".162" = shl i64 %".161", 32
  %".163" = or i64 %".160", %".162"
  %".164" = zext i8 0 to i64
  %".165" = shl i64 %".164", 40
  %".166" = or i64 %".163", %".165"
  %".167" = zext i8 0 to i64
  %".168" = shl i64 %".167", 48
  %".169" = or i64 %".166", %".168"
  %".170" = zext i8 0 to i64
  %".171" = shl i64 %".170", 56
  %".172" = or i64 %".169", %".171"
  ret i64 %".172"
}
