PROGRAM fermentation
  VAR_OUTPUT
    sp201 : INT;
    sp202 : INT;
    sp203 : INT;
    sp204 : INT;
  END_VAR
  VAR_EXTERNAL
    MASTER : BOOL;
  END_VAR
  VAR_INPUT
    Start : BOOL;
    Stop : BOOL;
    ultrasonic_level : INT;
  END_VAR
  VAR_OUTPUT
    cycle_on : BOOL;
    intake_pump_material_a : BOOL;
    intake_pump_material_b : BOOL;
    stop_intake_a : BOOL;
    stop_intake_b : BOOL;
    allow_intake_b : BOOL;
    agitator_motor : BOOL;
    stage_timer : BOOL;
    stage_completed : BOOL;
    stage_time : TIME;
    elapsed_stage_timer : TIME;
    elapsed_stage_time : INT;
    sp_agitator_speed : INT;
    next_stage : BOOL;
  END_VAR
  VAR_INPUT
    temp_sensor : INT;
  END_VAR
  VAR_OUTPUT
    stop_agitation : BOOL;
  END_VAR
  VAR
    TON1 : TON;
    _TMP_GE15_OUT : BOOL;
    _TMP_GE9_OUT : BOOL;
    _TMP_GE77_OUT : BOOL;
    _TMP_INT_TO_TIME72_OUT : TIME;
    _TMP_TIME_TO_INT79_OUT : INT;
  END_VAR

  cycle_on := NOT(Stop) AND (Start OR cycle_on);
  MASTER := NOT(Stop) AND (Start OR cycle_on);
  
  intake_pump_material_a := NOT(stop_intake_a) AND cycle_on;
  
  _TMP_GE15_OUT := GE(ultrasonic_level, sp201);
  stop_intake_a := cycle_on AND _TMP_GE15_OUT;
  
  intake_pump_material_b := NOT(stop_intake_b) AND (allow_intake_b OR intake_pump_material_b) AND 

  stop_intake_a AND cycle_on;
  
  _TMP_GE9_OUT := GE(temp_sensor, sp203);
  allow_intake_b := _TMP_GE9_OUT;
  
  _TMP_GE77_OUT := GE(ultrasonic_level, sp202);
  stop_intake_b := cycle_on AND _TMP_GE77_OUT;
  
  _TMP_INT_TO_TIME_MIN72_OUT := INT_TO_TIME_MIN(sp204);
  stage_time := _TMP_INT_TO_TIME_MIN72_OUT;
  
  agitator_motor := NOT(stop_agitation) AND (agitator_motor OR stop_intake_a) AND cycle_on;
  
  TON1(IN := next_stage AND cycle_on, PT := stage_time);
  stage_timer := TON1.Q;
  elapsed_stage_timer := TON1.ET;
  
  _TMP_TIME_TO_INT79_OUT := TIME_TO_INT(elapsed_stage_timer);
  elapsed_stage_time := _TMP_TIME_TO_INT79_OUT;
  
  stage_completed := stage_timer AND cycle_on;
END_PROGRAM

PROGRAM pressure_control
  VAR_EXTERNAL
    MASTER : BOOL;
  END_VAR
  VAR_OUTPUT
    sp208 : INT;
    sp209 : INT;
  END_VAR
  VAR_INPUT
    pressure_sensor : INT;
  END_VAR
  VAR_OUTPUT
    pressure_valve : BOOL;
    open_pressure_valve : BOOL;
    close_pressure_valve : BOOL;
  END_VAR
  VAR
    _TMP_ADD52_OUT : INT;
    _TMP_GT14_OUT : BOOL;
    _TMP_SUB48_OUT : INT;
    _TMP_LT51_OUT : BOOL;
  END_VAR

  pressure_valve := NOT(close_pressure_valve) AND open_pressure_valve AND MASTER;
  _TMP_ADD52_OUT := ADD(sp208, sp209);
  _TMP_GT14_OUT := GT(pressure_sensor, _TMP_ADD52_OUT);
  open_pressure_valve := MASTER AND _TMP_GT14_OUT;
  _TMP_SUB48_OUT := SUB(sp208, sp209);
  _TMP_LT51_OUT := LT(pressure_sensor, _TMP_SUB48_OUT);
  close_pressure_valve := MASTER AND _TMP_LT51_OUT;
END_PROGRAM

PROGRAM pH_control
  VAR_EXTERNAL
    MASTER : BOOL;
  END_VAR
  VAR_OUTPUT
    sp210 : INT;
    sp211 : INT;
    sp212 : INT;
    active : BOOL;
    base_pump : BOOL;
    base_start : BOOL;
    base_stop : BOOL;
    acid_pump : BOOL;
    acid_start : BOOL;
    acid_stop : BOOL;
  END_VAR
  VAR_INPUT
    ph_sensor : INT;
  END_VAR
  VAR
    _TMP_SUB48_OUT : INT;
    _TMP_LT51_OUT : BOOL;
    _TMP_ADD45_OUT : INT;
    _TMP_GT9_OUT : BOOL;
    _TMP_ADD52_OUT : INT;
    _TMP_GT14_OUT : BOOL;
    _TMP_SUB41_OUT : INT;
    _TMP_LT44_OUT : BOOL;
  END_VAR

  base_pump := NOT(base_stop) AND (base_pump OR base_start) AND MASTER;
  acid_pump := NOT(acid_stop) AND (acid_pump OR acid_start) AND MASTER;
  
  _TMP_SUB48_OUT := SUB(sp210, sp211);
  _TMP_LT51_OUT := LT(ph_sensor, _TMP_SUB48_OUT);
  base_start := MASTER AND _TMP_LT51_OUT;
  
  _TMP_ADD45_OUT := ADD(sp210, sp212);
  _TMP_GT9_OUT := GT(ph_sensor, _TMP_ADD45_OUT);
  acid_start := MASTER AND _TMP_GT9_OUT;
  
  _TMP_ADD52_OUT := ADD(sp210, sp211);
  _TMP_GT14_OUT := GT(ph_sensor, _TMP_ADD52_OUT);
  base_stop := MASTER AND _TMP_GT14_OUT;
  
  _TMP_SUB41_OUT := SUB(sp210, sp212);
  _TMP_LT44_OUT := LT(ph_sensor, _TMP_SUB41_OUT);
  acid_stop := MASTER AND _TMP_LT44_OUT;
END_PROGRAM

PROGRAM temperature_control
  VAR_EXTERNAL
    MASTER : BOOL;
  END_VAR
  VAR_OUTPUT
    sp205 : INT;
    sp206 : INT;
    sp207 : INT;
  END_VAR
  VAR_INPUT
    temp_sensor : INT;
  END_VAR
  VAR_OUTPUT
    heater : BOOL;
    heater_start : BOOL;
    heater_stop : BOOL;
    cooler : BOOL;
    cooler_start : BOOL;
    cooler_stop : BOOL;
  END_VAR
  VAR
    _TMP_SUB48_OUT : INT;
    _TMP_LT51_OUT : BOOL;
    _TMP_ADD45_OUT : INT;
    _TMP_GT9_OUT : BOOL;
    _TMP_ADD52_OUT : INT;
    _TMP_GT14_OUT : BOOL;
    _TMP_SUB41_OUT : INT;
    _TMP_LT44_OUT : BOOL;
  END_VAR

  heater := NOT(heater_stop) AND (heater OR heater_start) AND MASTER;
  cooler := NOT(cooler_stop) AND (cooler OR cooler_start) AND MASTER;
  
  _TMP_SUB48_OUT := SUB(sp205, sp207);
  _TMP_LT51_OUT := LT(temp_sensor, _TMP_SUB48_OUT);
  heater_start := MASTER AND _TMP_LT51_OUT;
  
  _TMP_ADD45_OUT := ADD(sp206, sp207);
  _TMP_GT9_OUT := GT(temp_sensor, _TMP_ADD45_OUT);
  cooler_start := MASTER AND _TMP_GT9_OUT;
 
  _TMP_ADD52_OUT := ADD(sp205, sp207);
  _TMP_GT14_OUT := GT(temp_sensor, _TMP_ADD52_OUT);
  heater_stop := MASTER AND _TMP_GT14_OUT;
  
  _TMP_SUB41_OUT := SUB(sp206, sp207);
  _TMP_LT44_OUT := LT(temp_sensor, _TMP_SUB41_OUT);
  cooler_stop := MASTER AND _TMP_LT44_OUT;
END_PROGRAM

PROGRAM od_control
  VAR_EXTERNAL
    MASTER : BOOL;
  END_VAR
  VAR_OUTPUT
    sp213 : INT;
    sp214 : INT;
  END_VAR
  VAR_INPUT
    do_sensor : INT;
  END_VAR
  VAR_OUTPUT
    aeration_valve : BOOL;
    open_valve : BOOL;
    close_valve : BOOL;
  END_VAR
  VAR
    _TMP_SUB48_OUT : INT;
    _TMP_LT51_OUT : BOOL;
    _TMP_ADD52_OUT : INT;
    _TMP_GE53_OUT : BOOL;
  END_VAR

  aeration_valve := NOT(close_valve) AND (aeration_valve OR open_valve) AND MASTER;
  
  _TMP_SUB48_OUT := SUB(sp213, sp214);
  _TMP_LT51_OUT := LT(do_sensor, _TMP_SUB48_OUT);
  open_valve := MASTER AND _TMP_LT51_OUT;
  
  _TMP_ADD52_OUT := ADD(sp213, sp214);
  _TMP_GE53_OUT := GE(do_sensor, _TMP_ADD52_OUT);
  close_valve := MASTER AND _TMP_GE53_OUT;
END_PROGRAM


CONFIGURATION Config0

  RESOURCE Res0 ON PLC
    VAR_GLOBAL
      MASTER : BOOL;
    END_VAR
    TASK task0(INTERVAL := T#20ms,PRIORITY := 0);
    TASK task1(INTERVAL := T#20ms,PRIORITY := 0);
    TASK task2(INTERVAL := T#20ms,PRIORITY := 0);
    TASK task3(INTERVAL := T#20ms,PRIORITY := 0);
    TASK task4(INTERVAL := T#20ms,PRIORITY := 0);
    PROGRAM instance0 WITH task0 : fermentation;
    PROGRAM instance2 WITH task0 : pressure_control;
    PROGRAM instance4 WITH task0 : od_control;
    PROGRAM instance1 WITH task1 : temperature_control;
    PROGRAM instance3 WITH task3 : pH_control;
  END_RESOURCE
END_CONFIGURATION
