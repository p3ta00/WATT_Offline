(*
    NOTE 1: The following setpoints are defined for use by third-party components and 
    are not directly manipulated by the PLC logic. These values are forwarded 
    to external devices, such as dispenser valves, for operational control. 
    This approach allows for centralized configuration while leveraging 
    specialized control mechanisms provided by the third-party hardware. 

    sp_bittering_hops_amount_1
    sp_bittering_hops_amount_2

    sp_flavor_hops_amount_1
    sp_flavor_hops_amount_2

    sp_aroma_hops_amount_1
    sp_aroma_hops_amount_2

    NOTE 2: The setpoints below are crucial for the operation of both the PLC and third-party components.

    sp_boil_time 
    sp_final_boil_time 
    sp_bittering_hops_time 
    sp_flavor_hops_time 
    sp_aroma_hops_time  

*)


PROGRAM boiling
  VAR_EXTERNAL
    master : BOOL;
    stop_intake_a : BOOL;
    kettle_temp : INT;
  END_VAR
  VAR_INPUT
    ultrasonic_level : INT;
  END_VAR
  VAR_OUTPUT
    boil_time : TIME;
    boil_timer : TIME;
  END_VAR
  VAR_INPUT
    start : BOOL;
    stop : BOOL;
  END_VAR
  VAR_OUTPUT
    cycle_on : BOOL;
    intake_pump_material_a : BOOL;
    agitator_motor : BOOL;
    end_boil : BOOL;
    output_valve : BOOL;
    ELS : BOOL;
    start_boil : BOOL;
    start_bittering_hops AT %QX1.1 : BOOL;
    start_aroma_hops AT %QX1.2 : BOOL;
    start_flavor_hops AT %QX1.3 : BOOL;
    final_boil : BOOL;
    sp_star_boil_timer_temp : INT;
    sp_agitator_speed : INT;
    sp_material_a : INT;
    sp_boil_time AT %MW3 : INT;
    sp_final_boil_time AT %MW4 : INT;
    sp_bittering_hops_time AT %MW5 : INT;
    sp_flavor_hops_time AT %MW6 : INT;
    sp_aroma_hops_time AT %MW7 : INT;
    sp_bittering_hops_amount_1 AT %MW1024 : INT;
    sp_bittering_hops_amount_2 AT %MW1025 : INT;
    sp_flavor_hops_amount_1 AT %MW1026 : INT;
    sp_flavor_hops_amount_2 AT %MW1027 : INT;
    sp_aroma_hops_amount_1 AT %MW1028 : INT;
    sp_aroma_hops_amount_2 AT %MW1029 : INT;
    boil_timer_int : INT;
  END_VAR
  VAR
    TON1 : TON;
    _TMP_INT_TO_TIME72_OUT : TIME;
    _TMP_GE15_OUT : BOOL;
    _TMP_GE14_OUT : BOOL;
    _TMP_TIME_TO_INT75_OUT : INT;
    _TMP_GE23_OUT : BOOL;
    _TMP_GE34_OUT : BOOL;
    _TMP_GE41_OUT : BOOL;
    _TMP_GE70_OUT : BOOL;
  END_VAR


  // Verify stop button is not pressed and start button pressed or cycle already started
  cycle_on := NOT(stop) AND (cycle_on OR start);
  master := NOT(stop) AND (cycle_on OR start);

  // Open intake valve until stop_intake is True
  intake_pump_material_a := NOT(stop_intake_a) AND cycle_on;

  // Stop intake of material a when desired level is reached
  _TMP_GE15_OUT := GE(ultrasonic_level, sp_material_a);
  stop_intake_a := cycle_on AND _TMP_GE15_OUT;
  
  // Start boiling
  _TMP_GE14_OUT := GE(kettle_temp, sp_star_boil_timer_temp);
  start_boil := cycle_on AND _TMP_GE14_OUT;
  
  // boil timer to int 
  _TMP_TIME_TO_INT75_OUT := TIME_TO_INT(boil_timer);
  boil_timer_int := _TMP_TIME_TO_INT75_OUT;
  
  // Coil control to signal when to start bittering hops addition 
  _TMP_GE23_OUT := GE(boil_timer_int, sp_bittering_hops_time);
  start_bittering_hops := NOT(start_flavor_hops) AND cycle_on AND _TMP_GE23_OUT;
  
  // Coil control to signal when to start flavor hops addition 
  _TMP_GE34_OUT := GE(boil_timer_int, sp_flavor_hops_time);
  start_flavor_hops := NOT(start_aroma_hops) AND cycle_on AND _TMP_GE34_OUT;
  
  // Coil control to signal when to start aroma hops addition 
  _TMP_GE41_OUT := GE(boil_timer_int, sp_aroma_hops_time);
  start_aroma_hops := NOT(final_boil) AND cycle_on AND _TMP_GE41_OUT;
  
  // Coil to signal final boil started
  _TMP_GE70_OUT := GE(boil_timer_int, sp_final_boil_time);
  final_boil := cycle_on AND _TMP_GE70_OUT;
  
  // Int to Time boil time
  _TMP_INT_TO_TIME72_OUT := INT_TO_TIME(sp_boil_time);
  boil_time := _TMP_INT_TO_TIME72_OUT;
 
  // Coil to control agitator motor
  agitator_motor := NOT(end_boil) AND (agitator_motor OR stop_intake_a) AND cycle_on;
 
  // Coil control to signal end of boiling time
  TON1(IN := start_boil AND cycle_on, PT := boil_time);
  end_boil := TON1.Q;
  boil_timer := TON1.ET;
 
  // Output valve control
  output_valve := NOT(ELS) AND (end_boil OR output_valve) AND cycle_on;
END_PROGRAM

PROGRAM pressure_control
  VAR_EXTERNAL
    master : BOOL;
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

  pressure_valve := NOT(close_pressure_valve) AND open_pressure_valve AND master;
  _TMP_ADD52_OUT := ADD(sp_pressure, 2);
  _TMP_GT14_OUT := GT(pressure_sensor, _TMP_ADD52_OUT);
  open_pressure_valve := master AND _TMP_GT14_OUT;
  _TMP_SUB48_OUT := SUB(sp_pressure, 2);
  _TMP_LT51_OUT := LT(pressure_sensor, _TMP_SUB48_OUT);
  close_pressure_valve := master AND _TMP_LT51_OUT;
END_PROGRAM

PROGRAM heating
  VAR_EXTERNAL
    master : BOOL;
    stop_intake_a : BOOL;
    kettle_temp : INT;
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
    _TMP_ADD45_OUT : INT;
    _TMP_GT9_OUT : BOOL;
    _TMP_ADD52_OUT : INT;
    _TMP_GT14_OUT : BOOL;
    _TMP_SUB41_OUT : INT;
    _TMP_LT44_OUT : BOOL;
  END_VAR

  heater := NOT(heater_stop) AND (heater OR heater_start) AND stop_intake_a AND master;
  _TMP_SUB48_OUT := SUB(sp_heater, 2);
  _TMP_LT51_OUT := LT(temp, _TMP_SUB48_OUT);
  heater_start := master AND _TMP_LT51_OUT;
  _TMP_ADD52_OUT := ADD(sp_heater, 2);
  _TMP_GT14_OUT := GT(temp, _TMP_ADD52_OUT);
  heater_stop := master AND _TMP_GT14_OUT;
  kettle_temp := temp;
  cooler := NOT(cooler_stop) AND (cooler OR cooler_start) AND stop_intake_a AND master;
  _TMP_ADD45_OUT := ADD(sp_cooler, 2);
  _TMP_GT9_OUT := GT(temp, _TMP_ADD45_OUT);
  cooler_start := master AND _TMP_GT9_OUT;
  _TMP_SUB41_OUT := SUB(sp_cooler, 2);
  _TMP_LT44_OUT := LT(temp, _TMP_SUB41_OUT);
  cooler_stop := master AND _TMP_LT44_OUT;

END_PROGRAM


CONFIGURATION Config0

  RESOURCE Res0 ON PLC
    VAR_GLOBAL
      master : BOOL;
      stop_intake_a : BOOL;
      kettle_temp : INT;
    END_VAR
    TASK task0(INTERVAL := T#1s0ms,PRIORITY := 0);
    TASK task1(INTERVAL := T#1s0ms,PRIORITY := 0);
    TASK task2(INTERVAL := T#1s0ms,PRIORITY := 0);
    PROGRAM instance0 WITH task0 : boiling;
    PROGRAM instance2 WITH task0 : pressure_control;
    PROGRAM instance1 WITH task1 : heating;
  END_RESOURCE
END_CONFIGURATION
