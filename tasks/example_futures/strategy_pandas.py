import pandas as pd
import numpy as np

class PandasTrendStrategy:
    """
    A pure Pandas implementation of the Dual MA Crossover strategy.
    Dependencies: only pandas and numpy.
    """
    
    def __init__(self, fast_ma=20, slow_ma=50, initial_capital=100000.0, commission=0.001):
        self.fast_ma = fast_ma
        self.slow_ma = slow_ma
        self.initial_capital = initial_capital
        self.commission = commission
        
    def run(self, df):
        # 1. Calculate Indicators
        df['fast_ma'] = df['close'].rolling(window=self.fast_ma).mean()
        df['slow_ma'] = df['close'].rolling(window=self.slow_ma).mean()
        
        # 2. Generate Signals (1: Buy/Long, 0: Neutral, -1: Sell/Short)
        # For simplicity: Long Only
        # Signal = 1 when Fast > Slow
        df['signal'] = np.where(df['fast_ma'] > df['slow_ma'], 1, 0)
        
        # 3. Calculate Positions (Shift 1 day to avoid look-ahead bias)
        # If signal today is 1, we buy at tomorrow's open
        df['position'] = df['signal'].shift(1)
        
        # 4. Calculate Returns
        # Strategy Return = Position * Market Return - Transaction Costs
        df['market_return'] = df['close'].pct_change()
        df['strategy_return'] = df['position'] * df['market_return']
        
        # 5. Transaction Costs
        # Cost is incurred when position changes
        # abs(pos - pos_prev) * commission
        df['trades'] = df['position'].diff().abs()
        df['cost'] = df['trades'] * self.commission
        
        df['net_strategy_return'] = df['strategy_return'] - df['cost']
        
        # 6. Calculate Equity Curve
        df['equity_curve'] = (1 + df['net_strategy_return']).cumprod() * self.initial_capital
        
        # Fill NaN (from rolling window)
        df.fillna(method='bfill', inplace=True)
        
        return df

if __name__ == "__main__":
    pass
