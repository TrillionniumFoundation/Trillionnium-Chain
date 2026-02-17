import pandas as pd
import json
import os
import sys
from strategy_pandas import PandasTrendStrategy
from data_generator import generate_trend_data

def run_backtest():
    # 1. Generate & Load Data
    data_file = "futures_data.csv"
    if not os.path.exists(data_file):
        print("Generating data...")
        df = generate_trend_data()
        df.to_csv(data_file, index=False)
    else:
        print("Loading existing data...")
        df = pd.read_csv(data_file)
        
    df['datetime'] = pd.to_datetime(df['datetime'])
    df.set_index('datetime', inplace=True)
    
    # 2. Run Strategy
    print("Running Pandas Strategy...")
    strategy = PandasTrendStrategy(initial_capital=100000.0)
    df = strategy.run(df)
    
    # 3. Calculate Final Results
    final_value = df['equity_curve'].iloc[-1]
    start_cash = strategy.initial_capital
    pnl = final_value - start_cash
    roi = (pnl / start_cash) * 100
    
    results = {
        "initial_capital": start_cash,
        "final_capital": final_value,
        "pnl": pnl,
        "roi_percent": roi,
        "status": "success",
        "trades_count": int(df['trades'].sum())
    }
    
    with open("results.json", "w") as f:
        json.dump(results, f, indent=4)
        
    print(f"Backtest complete.")
    print(f"Initial Capital: {start_cash}")
    print(f"Final Capital:   {final_value:.2f}")
    print(f"ROI:             {roi:.2f}%")
    print(f"Trades:          {int(df['trades'].sum())}")

if __name__ == '__main__':
    try:
        run_backtest()
    except Exception as e:
        print(f"Error running backtest: {e}")
        with open("results.json", "w") as f:
            json.dump({"status": "error", "message": str(e)}, f)
        sys.exit(1)
