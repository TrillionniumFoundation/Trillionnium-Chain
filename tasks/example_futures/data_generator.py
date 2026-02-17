import pandas as pd
import numpy as np
from datetime import datetime, timedelta

def generate_trend_data(days=365):
    """Generates synthetic futures OHLCV data with a trend."""
    np.random.seed(42)  # Fixed seed for reproducibility (Crucial for Verifiers!)
    
    dates = [datetime(2025, 1, 1) + timedelta(days=x) for x in range(days)]
    
    # Base trend: Sine wave + linear growth
    t = np.linspace(0, 4 * np.pi, days)
    trend = 100 + t * 5 + 10 * np.sin(t)
    
    # Add noise for volatility
    noise = np.random.normal(0, 2, days)
    close = trend + noise
    
    # Generate OHLC
    high = close + np.random.uniform(0, 3, days)
    low = close - np.random.uniform(0, 3, days)
    open_p = close + np.random.uniform(-1, 1, days)
    volume = np.random.randint(1000, 5000, days)
    
    df = pd.DataFrame({
        'datetime': dates,
        'open': open_p,
        'high': high,
        'low': low,
        'close': close,
        'volume': volume
    })
    
    # Ensure logical price consistency
    df['high'] = df[['open', 'close', 'high']].max(axis=1)
    df['low'] = df[['open', 'close', 'low']].min(axis=1)
    
    return df

if __name__ == "__main__":
    print("Generating synthetic futures data...")
    df = generate_trend_data()
    output_path = "futures_data.csv"
    df.to_csv(output_path, index=False)
    print(f"Data saved to {output_path}. Shape: {df.shape}")
