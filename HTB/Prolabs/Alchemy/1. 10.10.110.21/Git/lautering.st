PROGRAM lauter_tun
  VAR_INPUT
    start : BOOL;
    stop : BOOL;
    turbidity_sensor : INT;
    ultra_level_sensor : INT;
  END_VAR
  VAR_OUTPUT
    process_start : BOOL;
    output_valve : BOOL;
    intake_a : BOOL;
    sparge_water_valve : BOOL;
    stop_intake_a : BOOL;
    stop_sparge_water : BOOL;
    rake : BOOL;
    recirculation_pump : BOOL;
    rake_stop : BOOL;
    r_pump_stop : BOOL;
    settling_completed : BOOL;
    grain_removal : BOOL;
    stop_first_runoff : BOOL;
    stop_removal : BOOL;
    stop_final_runoff : BOOL;
    sp_mash_lvl AT %MW10 : INT;
    sp_sparge_water_temp AT %MW11 : INT;
    sp_settle_phase AT %MW51 : INT;
    sp_sparge_water_lvl AT %MW52 : INT;
    sp_first_runoff AT %MW44 : INT;
    sp_grain_bed_level AT %MW35 : INT;
    sp_turbidity_rake AT %MW23 : INT;
    sp_turbidity_vor AT %MW22 : INT;
  END_VAR
  VAR
    settle_phase_pt : TIME;
    settle_phase_et : TIME;
    sp_rake_timer : TIME;
    TON1 : TON;
    TON0 : TON;
    _TMP_GE28_OUT : BOOL;
    _TMP_INT_TO_TIME91_OUT : TIME;
    _TMP_LT62_OUT : BOOL;
    _TMP_LE89_OUT : BOOL;
    _TMP_LE102_OUT : BOOL;
    _TMP_GE107_OUT : BOOL;
    _TMP_LT123_OUT : BOOL;
    _TMP_LT114_OUT : BOOL;
  END_VAR

  process_start := NOT(stop) AND start;
  intake_a := NOT(stop_intake_a) AND process_start;
  _TMP_GE28_OUT := GE(ultra_level_sensor, sp_mash_lvl);
  stop_intake_a := process_start AND _TMP_GE28_OUT OR stop_intake_a AND process_start;
  _TMP_INT_TO_TIME91_OUT := INT_TO_TIME(sp_settle_phase);
  settle_phase_pt := _TMP_INT_TO_TIME91_OUT;
  TON0(IN := stop_intake_a AND process_start, PT := settle_phase_pt);
  settling_completed := TON0.Q;
  settle_phase_et := TON0.ET;
  rake := NOT(rake_stop) AND (rake OR settling_completed) AND process_start;
  _TMP_LT62_OUT := LT(turbidity_sensor, sp_turbidity_rake);
  TON1(IN := stop_intake_a AND process_start AND _TMP_LT62_OUT, PT := sp_rake_timer);
  rake_stop := TON1.Q;
  recirculation_pump := NOT(r_pump_stop) AND (recirculation_pump OR settling_completed) AND process_start;
  _TMP_LE89_OUT := LE(turbidity_sensor, sp_turbidity_vor);
  r_pump_stop := rake_stop AND process_start AND _TMP_LE89_OUT;
  output_valve := NOT(stop_first_runoff) AND (output_valve OR r_pump_stop) AND process_start;
  _TMP_LE102_OUT := LE(ultra_level_sensor, sp_first_runoff);
  stop_first_runoff := r_pump_stop AND process_start AND _TMP_LE102_OUT OR stop_first_runoff AND process_start;
  sparge_water_valve := NOT(stop_sparge_water) AND stop_first_runoff AND process_start;
  _TMP_GE107_OUT := GE(ultra_level_sensor, sp_sparge_water_lvl);
  stop_sparge_water := stop_first_runoff AND process_start AND _TMP_GE107_OUT OR stop_sparge_water;
  output_valve := NOT(stop_final_runoff) AND (output_valve OR stop_sparge_water) AND process_start;
  _TMP_LT123_OUT := LT(ultra_level_sensor, sp_grain_bed_level);
  stop_final_runoff := stop_sparge_water AND process_start AND _TMP_LT123_OUT;
  grain_removal := NOT(stop_removal) AND (grain_removal OR stop_final_runoff) AND process_start;
  _TMP_LT114_OUT := LT(ultra_level_sensor, 5);
  stop_removal := stop_final_runoff AND process_start AND _TMP_LT114_OUT;
END_PROGRAM


CONFIGURATION Config0

  RESOURCE Res0 ON PLC
    TASK task0(INTERVAL := T#1s0ms,PRIORITY := 0);
    PROGRAM instance0 WITH task0 : lauter_tun;
  END_RESOURCE
END_CONFIGURATION
