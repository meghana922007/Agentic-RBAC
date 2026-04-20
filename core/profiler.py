import cProfile
import pstats
import io
import os
import pandas as pd
from codecarbon import EmissionsTracker

def run_stress_test(run_pipeline_func, code: str, iterations: int = 100):
    """
    Runs the pipeline multiple times to generate measurable energy data using CodeCarbon
    and profiles the performance using cProfile to pinpoint bottlenecks.
    """
    # 1. Start CodeCarbon Tracker
    tracker = EmissionsTracker(
        project_name="rbac_compiler_stress_test",
        measure_power_secs=1,  # measure frequently
        output_dir=".",        # output emissions.csv to current dir
        log_level="error"      # suppress noisy logs
    )
    tracker.start()
    
    # 2. Start cProfile
    pr = cProfile.Profile()
    pr.enable()
    
    # 3. Run workload
    for _ in range(iterations):
        run_pipeline_func(code)
        
    # 4. Stop Profilers
    pr.disable()
    emissions_kg = tracker.stop()
    
    # 5. Process cProfile stats into a DataFrame
    s = io.StringIO()
    sortby = 'cumulative'
    ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
    ps.print_stats(30) # get top 30 to filter out noise
    
    # Parse the text output of pstats (skip header lines)
    lines = s.getvalue().split('\n')
    data = []
    
    start_parsing = False
    for line in lines:
        if "ncalls" in line and "tottime" in line:
            start_parsing = True
            continue
            
        if start_parsing and line.strip():
            parts = line.split()
            if len(parts) >= 6:
                try:
                    ncalls = parts[0]
                    tottime = float(parts[1])
                    cumtime = float(parts[3])
                    func_name = " ".join(parts[5:]) 
                    
                    # Filter out profiler noise
                    if "codecarbon" in func_name or "profiler.py" in func_name:
                        continue
                        
                    data.append({
                        "Calls": ncalls,
                        "Total Time (s)": tottime,
                        "Cumulative Time (s)": cumtime,
                        "Function / File": func_name
                    })
                except ValueError:
                    pass
    
    df_profile = pd.DataFrame(data).head(15) # top 15 bottlenecks
    
    return emissions_kg, df_profile
