PROGRAM pressure_control
  VAR_EXTERNAL
    MASTER : BOOL;
  END_VAR
  VAR_INPUT
    pressure_sensor : INT;
  END_VAR
  VAR_OUTPUT
    sp_pressure : INT;
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
  _TMP_ADD52_OUT := ADD(sp_pressure, 2);
  _TMP_GT14_OUT := GT(pressure_sensor, _TMP_ADD52_OUT);
  open_pressure_valve := MASTER AND _TMP_GT14_OUT;
  _TMP_SUB48_OUT := SUB(sp_pressure, 2);
  _TMP_LT51_OUT := LT(pressure_sensor, _TMP_SUB48_OUT);
  close_pressure_valve := MASTER AND _TMP_LT51_OUT;
END_PROGRAM

PROGRAM heating
  VAR_EXTERNAL
    MASTER : BOOL;
  END_VAR
  VAR_INPUT
    temp : INT;
  END_VAR
  VAR_OUTPUT
    heater : BOOL;
    sp_heater : INT := 64;
    heater_start : BOOL;
    heater_stop : BOOL;
    cooler : BOOL;
    sp_cooler : INT := 60;
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
  _TMP_SUB48_OUT := SUB(sp_heater, 2);
  _TMP_LT51_OUT := LT(temp, _TMP_SUB48_OUT);
  heater_start := MASTER AND _TMP_LT51_OUT;
  _TMP_ADD45_OUT := ADD(sp_cooler, 2);
  _TMP_GT9_OUT := GT(temp, _TMP_ADD45_OUT);
  cooler_start := MASTER AND _TMP_GT9_OUT;
  _TMP_ADD52_OUT := ADD(sp_heater, 2);
  _TMP_GT14_OUT := GT(temp, _TMP_ADD52_OUT);
  heater_stop := MASTER AND _TMP_GT14_OUT;
  _TMP_SUB41_OUT := SUB(sp_cooler, 2);
  _TMP_LT44_OUT := LT(temp, _TMP_SUB41_OUT);
  cooler_stop := MASTER AND _TMP_LT44_OUT;
END_PROGRAM

PROGRAM MIXER
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
    agitator_motor : BOOL;
    agitator_timer : BOOL;
    output_valve : BOOL;
    ELS : BOOL;
  END_VAR
  VAR
    agitator_time : TIME;
    elapsed_agitation_time : TIME;
  END_VAR
  VAR_OUTPUT
    elapsed_agitation : INT;
    sp_agitator_time : INT;
    sp_agitator_speed : INT;
    sp_material_a : INT;
    sp_material_b : INT;
  END_VAR
  VAR
    TON1 : TON;
    _TMP_INT_TO_TIME72_OUT : TIME;
    _TMP_GE15_OUT : BOOL;
    _TMP_TIME_TO_INT68_OUT : INT;
    _TMP_GE77_OUT : BOOL;
  END_VAR

  cycle_on := NOT(Stop) AND (Start OR cycle_on);
  _TMP_INT_TO_TIME72_OUT := INT_TO_TIME(sp_agitator_time);
  agitator_time := _TMP_INT_TO_TIME72_OUT;
  MASTER := NOT(Stop) AND (Start OR cycle_on)
  agitator_motor := NOT(agitator_timer) AND (agitator_motor OR stop_intake_a) AND cycle_on;
  intake_pump_material_a := NOT(stop_intake_a) AND (intake_pump_material_a AND cycle_on OR cycle_on);
  TON1(IN := stop_intake_b AND cycle_on, PT := agitator_time);
  agitator_timer := TON1.Q;
  elapsed_agitation_time := TON1.ET;
  _TMP_GE15_OUT := GE(ultrasonic_level, sp_material_a);
  stop_intake_a := cycle_on AND _TMP_GE15_OUT;
  _TMP_TIME_TO_INT68_OUT := TIME_TO_INT(elapsed_agitation_time);
  elapsed_agitation := _TMP_TIME_TO_INT68_OUT;
  intake_pump_material_b := NOT(stop_intake_b) AND stop_intake_a AND cycle_on;
  output_valve := NOT(ELS) AND (agitator_timer OR output_valve) AND cycle_on;
  _TMP_GE77_OUT := GE(ultrasonic_level, sp_material_b);
  stop_intake_b := cycle_on AND _TMP_GE77_OUT;
END_PROGRAM


CONFIGURATION Config0

  RESOURCE Res0 ON PLC
    VAR_GLOBAL
      MASTER : BOOL;
    END_VAR
    TASK task0(INTERVAL := T#1s0ms,PRIORITY := 0);
    TASK task1(INTERVAL := T#1s0ms,PRIORITY := 0);
    TASK task2(INTERVAL := T#1s0ms,PRIORITY := 0);
    PROGRAM instance0 WITH task0 : MIXER;
    PROGRAM instance2 WITH task0 : pressure_control;
    PROGRAM instance1 WITH task1 : heating;
  END_RESOURCE
END_CONFIGURATION
