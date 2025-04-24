PROGRAM botte_filling
  VAR_INPUT
    start : BOOL;
    stop : BOOL;
    overflow_sensor : BOOL;
    filling_sensor : BOOL;
    level_sensor : BOOL;
    capping_sensor : BOOL;
    cap_lazer_sensor : BOOL;
    empty_tank_sensor : BOOL;
  END_VAR
  VAR_OUTPUT
    process_start : BOOL;
    solenoid_valve : BOOL;
    motor_cap : BOOL;
    conveyor_motor : BOOL;
  END_VAR
  VAR
    batch_completed : BOOL;
    sp_beer_flow : INT;
    batch_no : INT;
    current_batch : INT;
    CTU0 : CTU;
    R_TRIG1 : R_TRIG;
  END_VAR

  process_start := NOT(empty_tank_sensor) AND NOT(overflow_sensor) AND NOT(stop) AND (process_start OR start);
  
  // Hardcoded value min:0 max:100
  sp_beer_flow := 5; 

  conveyor_motor := (NOT(motor_cap) OR NOT(capping_sensor)) AND process_start AND (NOT(solenoid_valve) OR NOT(filling_sensor));
  solenoid_valve := NOT(level_sensor) AND (filling_sensor OR solenoid_valve) AND process_start;
  motor_cap := NOT(cap_lazer_sensor) AND (capping_sensor OR motor_cap) AND process_start;
  R_TRIG1(CLK := motor_cap);
  CTU0(CU := R_TRIG1.Q, R := NOT(process_start), PV := batch_no);
  batch_completed := CTU0.Q;
  current_batch := CTU0.CV;
END_PROGRAM


CONFIGURATION Config0

  RESOURCE Res0 ON PLC
    TASK task0(INTERVAL := T#10ms,PRIORITY := 0);
    PROGRAM instance0 WITH task0 : botte_filling;
  END_RESOURCE
END_CONFIGURATION