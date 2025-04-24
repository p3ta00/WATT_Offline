PROGRAM pressure_control
  VAR_EXTERNAL
    master : BOOL;
  END_VAR
  VAR_INPUT
    pressure_sensor : INT := 10;
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

  pressure_valve := NOT(close_pressure_valve) AND open_pressure_valve AND master;
  _TMP_ADD52_OUT := ADD(sp_pressure, 2);
  _TMP_GT14_OUT := GT(pressure_sensor, _TMP_ADD52_OUT);
  open_pressure_valve := master AND _TMP_GT14_OUT;
  _TMP_SUB48_OUT := SUB(sp_pressure, 2);
  _TMP_LT51_OUT := LT(pressure_sensor, _TMP_SUB48_OUT);
  close_pressure_valve := master AND _TMP_LT51_OUT;
END_PROGRAM

PROGRAM temperature_control
  VAR_EXTERNAL
    master : BOOL;
  END_VAR
  VAR_INPUT
    temp : INT;
  END_VAR
  VAR_OUTPUT
    heater : BOOL;
    sp_heater : INT;
    heater_start : BOOL;
    heater_stop : BOOL;
    cooler : BOOL;
    sp_cooler : INT;
    cooler_start : BOOL;
    cooler_stop : BOOL;
  END_VAR
  VAR
    _TMP_SUB48_OUT : INT;
    _TMP_LT51_OUT : BOOL;
    _TMP_ADD52_OUT : INT;
    _TMP_GT14_OUT : BOOL;
    _TMP_ADD45_OUT : INT;
    _TMP_GT9_OUT : BOOL;
    _TMP_SUB41_OUT : INT;
    _TMP_LT44_OUT : BOOL;
  END_VAR

  heater := NOT(heater_stop) AND (heater OR heater_start) AND master;
  _TMP_SUB48_OUT := SUB(sp_heater, 2);
  _TMP_LT51_OUT := LT(temp, _TMP_SUB48_OUT);
  heater_start := master AND _TMP_LT51_OUT;
  _TMP_ADD52_OUT := ADD(sp_heater, 2);
  _TMP_GT14_OUT := GT(temp, _TMP_ADD52_OUT);
  heater_stop := master AND _TMP_GT14_OUT;
  cooler := NOT(cooler_stop) AND (cooler OR cooler_start) AND master;
  _TMP_ADD45_OUT := ADD(sp_cooler, 2);
  _TMP_GT9_OUT := GT(temp, _TMP_ADD45_OUT);
  cooler_start := master AND _TMP_GT9_OUT;
  _TMP_SUB41_OUT := SUB(sp_cooler, 2);
  _TMP_LT44_OUT := LT(temp, _TMP_SUB41_OUT);
  cooler_stop := master AND _TMP_LT44_OUT;
END_PROGRAM

PROGRAM conditioning
  VAR_EXTERNAL
    master : BOOL;
  END_VAR
  VAR_INPUT
    start : BOOL;
    stop : BOOL;
    open_output_valve : BOOL;
    ultrasonic_level : INT;
  END_VAR
  VAR_OUTPUT
    cycle_on : BOOL;
    intake_pump_material_a : BOOL;
    stop_intake_a : BOOL;
    output_valve : BOOL;
    conditioning_completed : BOOL;
    sp_conditioning_time : INT;
    sp_material_a : INT;
    elapsed_time : INT;
    conditioing_time : TIME;
    elapsed_time_t : TIME;
  END_VAR
  VAR
    TON0 : TON;
    _TMP_GE15_OUT : BOOL;
    _TMP_INT_TO_TIME67_OUT : TIME;
    _TMP_TIME_TO_INT68_OUT : INT;
  END_VAR

  cycle_on := NOT(stop) AND (cycle_on OR start);
  master := NOT(stop) AND (cycle_on OR start);
  intake_pump_material_a := NOT(stop_intake_a) AND cycle_on;
  _TMP_GE15_OUT := GE(ultrasonic_level, sp_material_a);
  stop_intake_a := cycle_on AND _TMP_GE15_OUT;
  _TMP_INT_TO_TIME67_OUT := INT_TO_TIME(sp_conditioning_time);
  conditioing_time := _TMP_INT_TO_TIME67_OUT;
  TON0(IN := stop_intake_a AND cycle_on, PT := conditioing_time);
  conditioning_completed := TON0.Q;
  elapsed_time_t := TON0.ET;
  _TMP_TIME_TO_INT68_OUT := TIME_TO_INT(elapsed_time_t);
  elapsed_time := _TMP_TIME_TO_INT68_OUT;
  output_valve := open_output_valve AND conditioning_completed AND cycle_on;
END_PROGRAM


CONFIGURATION Config0

  RESOURCE Res0 ON PLC
    VAR_GLOBAL
      master : BOOL;
    END_VAR
    TASK task0(INTERVAL := T#1s0ms,PRIORITY := 0);
    TASK task1(INTERVAL := T#1s0ms,PRIORITY := 0);
    TASK task2(INTERVAL := T#1s0ms,PRIORITY := 0);
    PROGRAM instance0 WITH task0 : conditioning;
    PROGRAM instance2 WITH task0 : pressure_control;
    PROGRAM instance1 WITH task1 : temperature_control;
  END_RESOURCE
END_CONFIGURATION
